/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2024 DataDirect Networks.

  This program can be distributed under the terms of the GNU GPLv2.
  See the file GPL2.txt.
*/

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 18)

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <time.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <string_view>
#include <cstdint>
#include <random>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <cfloat>
#include <fuse_lowlevel.h>
#include <fuse_opt.h>
#include <limits.h>

// memfs holds everything in memory and every mutation goes through the kernel,
// so cached attributes and dentries can never go stale. Hand the kernel an
// effectively unlimited validity timeout for both: calc_timeout_sec() /
// calc_timeout_nsec() in lib/fuse_lowlevel.c clamp it to ULONG_MAX seconds, so
// the kernel caches stats and attributes indefinitely and skips redundant
// getattr()/lookup() round-trips.
#define MEMFS_ATTR_TIMEOUT  DBL_MAX
#define MEMFS_ENTRY_TIMEOUT DBL_MAX

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

// Benchmark mode: bypass the content store so the FUSE interface itself is
// measured, not memfs's std::vector management. Writes still read the incoming
// buffer; reads still return data (served from a random scratch buffer).
struct memfs_config {
	int null_io;
	int fuse_dio;
	int writeback_cache;
	int parallel_direct_writes;
	int keep_cache;
	int debug_io;
	// Hand each regular file's memfd to the kernel as a passthrough backing
	// file so READ/WRITE are served in-kernel without a round-trip to the
	// daemon. On by default; see memfs_init() for the kernel negotiation and
	// main() for the flags that force it off (null_io, fuse_dio).
	int passthrough;
	// Read-pipeline depth knobs. 0 means "use the memfs default" (see
	// memfs_init), which is deliberately deeper than libfuse's stock
	// max_background=12 / congestion_threshold=9.
	unsigned max_background;
	unsigned congestion_threshold;
	unsigned max_readahead;
	// Largest FUSE_WRITE the daemon negotiates (bytes). 0 selects the running
	// kernel's ceiling; see memfs_max_write_ceiling() and memfs_init().
	unsigned max_write;
	// redfs simulation: when set, a background thread periodically fires a
	// storm of cache invalidations at random currently-open files, mimicking
	// peer nodes mutating them underneath us. Off by default so the
	// benchmark modes and the xfstests harness are unaffected.
	int notify_inval;
	// Upper bound (in milliseconds) on the randomized delay between
	// invalidation storms; 0 selects MEMFS_DEFAULT_NOTIFY_INTERVAL_MS.
	unsigned notify_interval_ms;
	// Number of invalidations fired back-to-back in each storm; 0 selects
	// MEMFS_DEFAULT_NOTIFY_STORM.
	unsigned notify_storm;
};
static struct memfs_config memfs_cfg;

// memfs default read-pipeline depth. A single sequential reader serves each
// READ from RAM, so its cost is dominated by the FUSE request/reply round-trip
// rather than any work. The kernel only keeps max_background readahead requests
// in flight (FUSE_DEFAULT_MAX_BACKGROUND = 12) and stops issuing readahead once
// congestion_threshold (9) is reached (see fuse_readahead() in fs/fuse/file.c),
// so the reader repeatedly catches up to the in-flight readahead and blocks one
// folio at a time. Negotiating a deeper pipeline lets readahead run far enough
// ahead to hide the round-trip latency.
#define MEMFS_DEFAULT_MAX_BACKGROUND 64
#define MEMFS_DEFAULT_MAX_READAHEAD  (4u << 20) /* 4 MiB: max fuse-uring buffer */

// Defaults for the -o notify_inval redfs simulation: the upper bound on the
// random delay between invalidation storms (notify_interval_ms) and the number
// of invalidations fired back-to-back in each storm (notify_storm).
#define MEMFS_DEFAULT_NOTIFY_INTERVAL_MS 1000
#define MEMFS_DEFAULT_NOTIFY_STORM 64

#define MEMFS_OPT(t, p) { t, offsetof(struct memfs_config, p), 1 }
#define MEMFS_OPT_NUM(t, p) { t, offsetof(struct memfs_config, p), 0 }
static const struct fuse_opt memfs_opt_spec[] = {
	MEMFS_OPT("null_io", null_io),
	MEMFS_OPT("fuse_dio", fuse_dio),
	MEMFS_OPT("writeback_cache", writeback_cache),
	MEMFS_OPT("parallel_direct_writes", parallel_direct_writes),
	MEMFS_OPT("keep_cache", keep_cache),
	MEMFS_OPT("debug_io", debug_io),
	MEMFS_OPT("passthrough", passthrough),
	// -o no_passthrough clears the default-on flag (value 0).
	{ "no_passthrough", offsetof(struct memfs_config, passthrough), 0 },
	MEMFS_OPT_NUM("max_background=%u", max_background),
	MEMFS_OPT_NUM("congestion_threshold=%u", congestion_threshold),
	MEMFS_OPT_NUM("max_readahead=%u", max_readahead),
	MEMFS_OPT_NUM("max_write=%u", max_write),
	MEMFS_OPT("notify_inval", notify_inval),
	MEMFS_OPT_NUM("notify_interval_ms=%u", notify_interval_ms),
	MEMFS_OPT_NUM("notify_storm=%u", notify_storm),
	FUSE_OPT_END
};

// -o debug_io: log every READ/WRITE (offset, size, end) to stderr with a
// timestamp.  Useful for watching the deferred read-modify-write algorithm:
// writes arrive as the application writes, while the gap reads that complete a
// partially written block show up later, at flush time (and not at all once a
// block has been fully written).
static const std::chrono::steady_clock::time_point memfs_start_time =
	std::chrono::steady_clock::now();

static void memfs_log_io(const char *op, fuse_ino_t ino, off_t offset,
			 size_t size)
{
	if (!memfs_cfg.debug_io)
		return;

	double t = std::chrono::duration<double>(
			   std::chrono::steady_clock::now() - memfs_start_time)
			   .count();
	fprintf(stderr,
		"[%10.3f] memfs %-5s ino=%ju off=%jd size=%zu end=%jd\n",
		t, op, (uintmax_t)ino, (intmax_t)offset, size,
		(intmax_t)(offset + (off_t)size));
}

static const char *memfs_dlm_type_str(uint32_t type)
{
	switch (type) {
	case FUSE_LL_DLM_LOCK_NONE:	return "NONE";
	case FUSE_LL_DLM_LOCK_READ:	return "READ";
	case FUSE_LL_DLM_LOCK_WRITE:	return "WRITE";
	default:			return "?";
	}
}

// Log a DLM lock request.  Under writeback caching the kernel takes a
// page-rounded write lock over the region it is about to dirty before the
// writes go out, so these lines mark the start of each cached write burst and
// their [start, end] is the page-aligned span that the gap reads later fall in.
static void memfs_log_dlm(fuse_ino_t ino, uint64_t start, uint64_t end,
			  uint32_t type)
{
	if (!memfs_cfg.debug_io)
		return;

	double t = std::chrono::duration<double>(
			   std::chrono::steady_clock::now() - memfs_start_time)
			   .count();
	fprintf(stderr,
		"[%10.3f] memfs DLM   ino=%ju start=%ju end=%ju len=%ju type=%s\n",
		t, (uintmax_t)ino, (uintmax_t)start, (uintmax_t)end,
		(uintmax_t)(end - start + 1), memfs_dlm_type_str(type));
}

// -o debug_io: log each background cache invalidation (see memfs_notify_storm)
// using the same timestamped format as the read/write log lines.
static void memfs_log_notify(fuse_ino_t ino, off_t off)
{
	if (!memfs_cfg.debug_io)
		return;

	double t = std::chrono::duration<double>(
			   std::chrono::steady_clock::now() - memfs_start_time)
			   .count();
	fprintf(stderr, "[%10.3f] memfs NOTIFY ino=%ju scope=%s\n", t,
		(uintmax_t)ino, off < 0 ? "attr" : "data+attr");
}

// Random bytes filled once at startup; null_io reads copy/tile from here so the
// per-read cost stays close to a memcpy rather than a per-byte RNG.
static constexpr size_t NULL_IO_BUF_SIZE = 1u << 20;
static std::vector<char> null_io_buf;

// null_io writes fold the incoming buffer into this volatile sink so the
// compiler cannot elide the reads that simulate the data transfer.
static volatile unsigned char null_io_write_sink;

static void null_io_fill(char *dst, size_t size)
{
	size_t copied = 0;
	while (copied < size) {
		size_t chunk = std::min(size - copied, null_io_buf.size());
		std::copy(null_io_buf.begin(), null_io_buf.begin() + chunk,
			  dst + copied);
		copied += chunk;
	}
}

class Inodes;
class Inode;
class Dentry;

static void memfs_panic(std::string_view message);

struct DirHandle {
	std::vector<std::pair<std::string, std::shared_ptr<Inode> > > entries;
	size_t offset;

	DirHandle(const std::vector<
		  std::pair<std::string, std::shared_ptr<Inode> > > &entries)
		: entries(entries)
		, offset(0)
	{
	}
};

class Inode {
    private:
	uint64_t ino; // Unique inode number
	std::string name;
	bool is_dir_;
	time_t ctime;
	time_t mtime;
	time_t atime;
	mode_t mode;
	// A regular file's data lives in an anonymous, RAM-backed memfd instead
	// of a std::vector, so the kernel can be handed the fd as a passthrough
	// backing file and serve READ/WRITE directly against it (see
	// open_passthrough()).  -1 for directories, special files and the
	// null_io benchmark mode, which have no content store.
	int backing_fd{ -1 };
	// Passthrough registration id returned by fuse_passthrough_open(), shared
	// across all opens of this inode and torn down on the last release.  0
	// means "no passthrough registered".  Guarded by backing_mutex together
	// with nopen (the open reference count that decides when to tear it down).
	int backing_id{ 0 };
	unsigned nopen{ 0 };
	mutable std::mutex backing_mutex;
	// Logical size high-water mark for null_io, which bypasses the memfd:
	// writes and truncates record the file size here and get_attr() reports
	// it. Unused once a backing_fd exists (fstat() is authoritative then).
	std::atomic<off_t> size_{ 0 };
	// Children of a directory, keyed by name so lookup/insert/remove are
	// O(1) instead of an O(n) linear scan (creating N files in one
	// directory was O(N^2)). readdir enumerates a snapshot taken at
	// opendir time, so the map's unordered iteration order is irrelevant.
	// Empty for non-directories.
	std::unordered_map<std::string, Dentry *> dentries;
	mutable std::shared_mutex mutex;
	uint64_t nlookup;
	mutable std::mutex attr_mutex;
	std::atomic<nlink_t> nlink;
	uid_t uid;
	gid_t gid;
	dev_t rdev;

	friend class Inodes;

    public:
	Inode(uint64_t ino, const std::string &n, bool dir)
		: ino(ino)
		, name(n)
		, is_dir_(dir)
		, ctime(time(NULL))
		, mtime(ctime)
		, atime(ctime)
		, mode(dir ? S_IFDIR | 0755 : S_IFREG | 0644)
		, nlookup(1)
		, nlink(dir ? 2 : 1)
		, uid(0)
		, gid(0)
		, rdev(0)
	{
	}

	~Inode()
	{
		// nopen has reached 0 by the time an inode is reclaimed (the
		// kernel never forgets an inode with open files), so the
		// passthrough registration is already gone; only the memfd,
		// which holds the file's data, is left to close. Closing it
		// frees the backing pages.
		if (backing_fd >= 0)
			close(backing_fd);
	}

	uint64_t get_ino() const
	{
		return ino;
	}

	// Method to lock the mutex
	void lock() const
	{
		mutex.lock();
	}

	// Method to unlock the mutex
	void unlock() const
	{
		mutex.unlock();
	}

	void inc_lookup()
	{
		std::lock_guard<std::shared_mutex> lock(mutex);
		nlookup++;
	}

	uint64_t dec_lookup(uint64_t count)
	{
		std::unique_lock<std::shared_mutex> lock(mutex);
		if (nlookup < count) {
			lock.unlock();
			memfs_panic("Lookup count mismatch detected");
		}
		nlookup -= count;
		return nlookup;
	}

	const std::string &get_name() const
	{
		return name;
	}
	bool is_dir() const
	{
		return is_dir_;
	}
	time_t get_ctime() const
	{
		return ctime;
	}
	time_t get_mtime() const
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		return mtime;
	}
	mode_t get_mode() const
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		return mode;
	}

	// Current logical file size: the memfd length for regular files (kept
	// up to date by passthrough writes the daemon never sees), otherwise the
	// null_io high-water mark.
	off_t current_size() const
	{
		if (backing_fd >= 0) {
			struct stat st;
			if (fstat(backing_fd, &st) == 0)
				return st.st_size;
			return 0;
		}
		return size_.load(std::memory_order_relaxed);
	}

	size_t content_size() const
	{
		return current_size();
	}

	// Record a write extent for null_io (no data stored): a lock-free
	// high-water-mark bump so the file still reports a non-zero size.
	void grow_size(off_t end)
	{
		off_t cur = size_.load(std::memory_order_relaxed);
		while (end > cur &&
		       !size_.compare_exchange_weak(cur, end,
						    std::memory_order_relaxed))
			;
	}

	// pread/pwrite the memfd directly: the kernel serializes concurrent
	// access to the fd, so no inode lock is needed here (unlike the old
	// std::vector store). Returns the syscall result / -1 with errno set.
	ssize_t read_content(char *buf, size_t size, off_t offset) const
	{
		if (backing_fd < 0)
			return 0;
		return pread(backing_fd, buf, size, offset);
	}

	ssize_t write_content(const char *buf, size_t size, off_t offset)
	{
		if (backing_fd < 0) {
			errno = EIO;
			return -1;
		}
		return pwrite(backing_fd, buf, size, offset);
	}

	void set_uid(uid_t _uid)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		uid = _uid;
	}

	void set_gid(gid_t _gid)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		gid = _gid;
	}

	void set_mode(mode_t new_mode)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		mode = new_mode;
	}

	// FUSE_CAP_HANDLE_KILLPRIV_V2 contract: the daemon, not the kernel,
	// strips privilege bits on write/truncate/chown. Same policy as the
	// kernel's setattr_should_drop_suidgid(): suid always dies; sgid dies
	// only when group-exec is set (sgid without group-exec means mandatory
	// locking and must survive). memfs has no xattrs, so the
	// security.capability half of the contract is vacuously satisfied.
	void kill_suidgid()
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		if (!S_ISREG(mode))
			return;
		mode &= ~S_ISUID;
		if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))
			mode &= ~S_ISGID;
	}

	void set_rdev(dev_t new_rdev)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		rdev = new_rdev;
	}

	// Set atime and/or mtime. Each timespec uses the futimens() conventions:
	// tv_nsec == UTIME_OMIT leaves that timestamp unchanged, UTIME_NOW sets
	// it to the current time. A regular file's timestamps live on its memfd
	// (passthrough writes bump them in-kernel behind the daemon's back), so
	// apply them there with a single futimens(); directories and special
	// files keep their timestamps in the inode.
	void set_times(const struct timespec &_atime, const struct timespec &_mtime)
	{
		if (backing_fd >= 0) {
			struct timespec ts[2] = { _atime, _mtime };
			futimens(backing_fd, ts);
			return;
		}

		struct timespec now = { 0, 0 };
		if (_atime.tv_nsec == UTIME_NOW || _mtime.tv_nsec == UTIME_NOW)
			clock_gettime(CLOCK_REALTIME, &now);

		std::lock_guard<std::mutex> lock(attr_mutex);
		if (_atime.tv_nsec != UTIME_OMIT)
			atime = (_atime.tv_nsec == UTIME_NOW) ? now.tv_sec :
								_atime.tv_sec;
		if (_mtime.tv_nsec != UTIME_OMIT)
			mtime = (_mtime.tv_nsec == UTIME_NOW) ? now.tv_sec :
								_mtime.tv_sec;
	}

	// Returns 0 or an errno. For a regular file this ftruncate()s the memfd,
	// which is what the kernel reads back through passthrough; null_io keeps
	// only the size high-water mark.
	int truncate(off_t size)
	{
		if (backing_fd >= 0)
			return ftruncate(backing_fd, size) < 0 ? errno : 0;

		std::lock_guard<std::mutex> lock(attr_mutex);
		size_.store(size, std::memory_order_relaxed);
		mtime = time(NULL);
		return 0;
	}

	void get_attr(struct stat *stbuf) const
	{
		// Ownership of a regular file's attributes is split: the memfd
		// owns the data-derived fields (size, blocks, and the a/m/ctime
		// that passthrough writes update in-kernel behind the daemon's
		// back), while the inode owns identity and permissions
		// (mode/uid/gid/nlink/rdev). A single fstat() gives a consistent
		// snapshot of the former; attr_mutex guards the latter.
		std::lock_guard<std::mutex> attr_lock(attr_mutex);
		stbuf->st_ino = ino;
		stbuf->st_mode = mode;
		stbuf->st_nlink = nlink;
		stbuf->st_uid = uid;
		stbuf->st_gid = gid;
		stbuf->st_rdev = rdev;

		struct stat bst;
		if (backing_fd >= 0 && fstat(backing_fd, &bst) == 0) {
			stbuf->st_size = bst.st_size;
			stbuf->st_blocks = bst.st_blocks;
			stbuf->st_atime = bst.st_atime;
			stbuf->st_mtime = bst.st_mtime;
			stbuf->st_ctime = bst.st_ctime;
		} else {
			off_t fsize = size_.load(std::memory_order_relaxed);
			stbuf->st_size = fsize;
			stbuf->st_blocks = DIV_ROUND_UP(fsize, 512);
			stbuf->st_atime = atime;
			stbuf->st_mtime = mtime;
			stbuf->st_ctime = ctime;
		}
	}

	// Create the memfd that stores this regular file's data. Called once,
	// at creation time; null_io keeps no store and leaves backing_fd == -1.
	// Returns false only if memfd_create() itself fails.
	bool init_backing()
	{
		if (memfs_cfg.null_io)
			return true;
		int fd = memfd_create("memfs", MFD_CLOEXEC);
		if (fd < 0)
			return false;
		backing_fd = fd;
		return true;
	}

	// Register the memfd with the kernel as a passthrough backing file on
	// the first open and return the shared backing id for fi->backing_id;
	// later opens of the same inode reuse it. Returns 0 when passthrough is
	// unavailable (no memfd, or the ioctl failed), so the caller falls back
	// to daemon-served read/write.
	int open_passthrough(fuse_req_t req)
	{
		std::lock_guard<std::mutex> lock(backing_mutex);
		nopen++;
		if (backing_fd < 0)
			return 0;
		if (backing_id == 0)
			backing_id = fuse_passthrough_open(req, backing_fd);
		return backing_id;
	}

	// Balance one open_passthrough(); on the last release tear down the
	// shared backing registration. The memfd stays open for the inode's
	// lifetime so a later open can re-register it.
	void close_passthrough(fuse_req_t req)
	{
		std::lock_guard<std::mutex> lock(backing_mutex);
		if (nopen > 0)
			nopen--;
		if (nopen == 0 && backing_id != 0) {
			fuse_passthrough_close(req, backing_id);
			backing_id = 0;
		}
	}

	bool is_empty() const
	{
		std::shared_lock<std::shared_mutex> lock(mutex);
		return dentries.empty();
	}

	void inc_nlink()
	{
		nlink++;
	}

	nlink_t dec_nlink()
	{
		nlink_t old_value =
			nlink.fetch_sub(1, std::memory_order_relaxed);
		if (old_value == 0) {
			memfs_panic("Attempting to decrement nlink below zero");
		}
		return old_value - 1;
	}

	nlink_t get_nlink() const
	{
		return nlink.load(std::memory_order_relaxed);
	}

	/**
	  * Methods that need Dentry knowledge
	  */
	int add_child_locked(const std::string &name, Dentry *child_dentry);
	int add_child(const std::string &name, Dentry *child_dentry);
	int remove_child(const std::string &name);
	std::vector<std::pair<std::string, std::shared_ptr<Inode> > >
	get_children() const;
	Dentry *find_child_locked(const std::string &name) const;
	Dentry *find_child(const std::string &name) const;
	// Resolve a child to its inode under a shared lock, copying the
	// shared_ptr before releasing so the result stays valid. Used by the
	// lookup hot path, which only reads and so must not take the parent's
	// exclusive lock.
	std::shared_ptr<Inode> lookup_child(const std::string &name) const;
};

class Dentry {
    public:
	std::string name;
	std::shared_ptr<Inode> inode;

	Dentry(const std::string &n, std::shared_ptr<Inode> i)
		: name(n)
		, inode(std::move(i))
	{
	}

	uint64_t get_ino() const
	{
		return inode->get_ino();
	}
	bool is_dir() const
	{
		return inode->is_dir();
	}
	const std::string &get_name() const
	{
		return name;
	}

	time_t get_ctime() const
	{
		return inode->get_ctime();
	}
	time_t get_mtime() const
	{
		return inode->get_mtime();
	}
	mode_t get_mode() const
	{
		return inode->get_mode();
	}
	size_t content_size() const
	{
		return inode->content_size();
	}

	Inode *get_inode() const
	{
		return inode.get();
	}

	void inc_lookup()
	{
		inode->inc_lookup();
	}
};

class Inodes {
    private:
	std::unordered_map<uint64_t, std::shared_ptr<Inode> > inodes;
	mutable std::shared_mutex inodes_mutex;
	std::atomic<uint64_t> next_ino{ FUSE_ROOT_ID + 1 };

    public:
	Inodes()
	{
		auto root = std::make_shared<Inode>(FUSE_ROOT_ID, "/", true);
		root->mode = S_IFDIR | 0755;
		root->nlink = 2; // . and ..
		inodes[FUSE_ROOT_ID] = std::move(root);
	}

	// New lock method
	void lock()
	{
		inodes_mutex.lock();
	}

	// New unlock method
	void unlock()
	{
		inodes_mutex.unlock();
	}

	void erase_locked(Inode *inode)
	{
		if (inode) {
			inodes.erase(inode->get_ino());
		}
	}

	void erase(Inode *inode)
	{
		std::unique_lock<std::shared_mutex> lock(inodes_mutex);
		erase_locked(inode);
	}

	std::shared_ptr<Inode> find_locked(fuse_ino_t ino)
	{
		auto it = inodes.find(ino);
		if (it == inodes.end()) {
			return nullptr;
		}
		return it->second;
	}

	std::shared_ptr<Inode> find(fuse_ino_t ino)
	{
		std::shared_lock lock(inodes_mutex);
		return find_locked(ino);
	}

	std::shared_ptr<Inode> create(const std::string &name, bool is_dir,
				      mode_t mode)
	{
		std::unique_lock<std::shared_mutex> lock(inodes_mutex);

		uint64_t ino = next_ino.fetch_add(1, std::memory_order_relaxed);
		auto new_inode = std::make_shared<Inode>(ino, name, is_dir);
		new_inode->set_mode(mode);

		// Give every regular file its RAM-backed memfd store up front, so
		// read/write/getattr/truncate and passthrough all have an fd to
		// work with. Directories and special files (S_IFIFO/S_IFCHR/...)
		// carry no data store. A memfd_create() failure fails the create.
		if (S_ISREG(mode) && !new_inode->init_backing())
			return nullptr;

		auto [it, inserted] = inodes.emplace(ino, std::move(new_inode));

		if (!inserted) {
			// This should never happen, but let's handle it just in case
			return nullptr;
		}

		return it->second;
	}

	size_t size() const
	{
		std::shared_lock<std::shared_mutex> lock(inodes_mutex);
		return inodes.size();
	}
};

int Inode::add_child_locked(const std::string &name, Dentry *child_dentry)
{
	if (!is_dir_) {
		return ENOTDIR;
	}

	// Check if a child with this name already exists
	auto [it, inserted] = dentries.emplace(name, child_dentry);
	if (!inserted) {
		return EEXIST;
	}

	if (child_dentry->is_dir()) {
		nlink++;
	}
	return 0;
}

int Inode::add_child(const std::string &name, Dentry *child_dentry)
{
	std::lock_guard<std::shared_mutex> lock(mutex);
	return add_child_locked(name, child_dentry);
}

int Inode::remove_child(const std::string &name)
{
	if (!is_dir_) {
		return ENOTDIR;
	}

	auto it = dentries.find(name);
	if (it == dentries.end()) {
		return ENOENT;
	}

	Dentry *child_dentry = it->second;
	dentries.erase(it);

	if (child_dentry->is_dir()) {
		nlink--;
	}

	delete child_dentry;
	return 0;
}
Dentry *Inode::find_child_locked(const std::string &name) const
{
	if (!is_dir_) {
		return nullptr;
	}

	auto it = dentries.find(name);
	return (it != dentries.end()) ? it->second : nullptr;
}

Dentry *Inode::find_child(const std::string &name) const
{
	std::shared_lock<std::shared_mutex> lock(mutex);
	return find_child_locked(name);
}

std::shared_ptr<Inode> Inode::lookup_child(const std::string &name) const
{
	std::shared_lock<std::shared_mutex> lock(mutex);
	Dentry *child = find_child_locked(name);
	return child ? child->inode : nullptr;
}

std::vector<std::pair<std::string, std::shared_ptr<Inode> > >
Inode::get_children() const
{
	std::shared_lock<std::shared_mutex> lock(mutex);
	if (!is_dir_) {
		return {}; // Return an empty vector if this is not a directory
	}

	std::vector<std::pair<std::string, std::shared_ptr<Inode> > > children;
	children.reserve(dentries.size());

	for (const auto &kv : dentries) {
		const Dentry *dentry = kv.second;
		children.emplace_back(dentry->name, dentry->inode);
	}

	return children;
}
static Inodes Inodes;

// Set of inodes with at least one open file handle, maintained by
// memfs_open()/memfs_create() and memfs_release(). The background invalidator
// (memfs_notify_storm) draws its random victims from here, so only files the
// kernel currently has open -- and therefore has cached state for -- are
// targeted.
// Refcounted because the same inode can be opened by several handles at once.
class OpenFiles {
	std::unordered_map<fuse_ino_t, unsigned> counts;
	mutable std::mutex mutex;

    public:
	void add(fuse_ino_t ino)
	{
		std::lock_guard<std::mutex> lock(mutex);
		counts[ino]++;
	}

	void remove(fuse_ino_t ino)
	{
		std::lock_guard<std::mutex> lock(mutex);
		auto it = counts.find(ino);
		if (it != counts.end() && --it->second == 0)
			counts.erase(it);
	}

	// Return a uniformly-chosen currently-open inode, or 0 if none.
	fuse_ino_t pick_random(std::mt19937 &rng) const
	{
		std::lock_guard<std::mutex> lock(mutex);
		if (counts.empty())
			return 0;
		std::uniform_int_distribution<size_t> dist(0, counts.size() - 1);
		auto it = counts.begin();
		std::advance(it, dist(rng));
		return it->first;
	}
};
static OpenFiles open_files;

static int do_memfs_lookup(fuse_ino_t parent, const char *name,
			   struct fuse_entry_param *e)
{
	auto parentInode = Inodes.find(parent);

	if (!parentInode)
		return ENOENT;

	if (!parentInode->is_dir())
		return ENOTDIR;

	// Lookup only reads the parent's dentry map, so take a shared lock (not
	// the exclusive lock()/unlock()) to let concurrent lookups in the same
	// directory proceed in parallel. lookup_child() copies the child's
	// shared_ptr under that lock, so the result stays valid afterwards.
	std::shared_ptr<Inode> child_inode = parentInode->lookup_child(name);
	if (!child_inode)
		return ENOENT;

	memset(e, 0, sizeof(*e));
	e->ino = child_inode->get_ino();
	e->attr_timeout = MEMFS_ATTR_TIMEOUT;
	e->entry_timeout = MEMFS_ENTRY_TIMEOUT;
	child_inode->get_attr(&e->attr);

	child_inode->inc_lookup();

	return 0;
}

static void memfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;
	int err = do_memfs_lookup(parent, name, &e);
	if (err) {
		fuse_reply_err(req, err);
		return;
	}

	fuse_reply_entry(req, &e);
}

static void memfs_lookupx(fuse_req_t req, fuse_ino_t parent, const char *name,
			  [[maybe_unused]] uint32_t flags)
{
	struct fuse_entry_param e;
	int err = do_memfs_lookup(parent, name, &e);
	if (err) {
		fuse_reply_err(req, err);
		return;
	}

	/* do_memfs_lookup() populates e.attr via Inode::get_attr(), which fills
	 * every basic-stat field, so advertise the full basic-stats mask.
	 */
	fuse_reply_lookupx(req, &e, STATX_BASIC_STATS);
}

static void memfs_getattr(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	// open()/create() cache the Inode* in fi->fh; a request without fi is
	// path-based, so resolve it through the inode number instead.
	std::shared_ptr<Inode> inode_holder;
	Inode *inode;
	if (fi) {
		inode = reinterpret_cast<Inode *>(fi->fh);
		if (!inode) {
			fuse_reply_err(req, EBADF);
			return;
		}
	} else {
		inode_holder = Inodes.find(ino);
		if (!inode_holder) {
			fuse_reply_err(req, ENOENT);
			return;
		}
		inode = inode_holder.get();
	}

	struct stat stbuf;
	inode->get_attr(&stbuf);

	fuse_reply_attr(req, &stbuf, MEMFS_ATTR_TIMEOUT);
}

// Fill in the open-reply flags shared by open() and create(). Prefer
// passthrough: hand the kernel the inode's memfd so it serves read/write in
// the kernel, bypassing the daemon entirely. Otherwise fall back to the
// direct-I/O / page-cache knobs.
static void memfs_setup_file_open(fuse_req_t req, Inode *inode,
				  struct fuse_file_info *fi)
{
	// Cache the resolved Inode* in the handle so read/write/release skip the
	// global Inodes lookup. The inode outlives the open (the kernel never
	// forgets an inode with open files), so this pointer never dangles.
	fi->fh = reinterpret_cast<uint64_t>(inode);

	if (memfs_cfg.passthrough) {
		int backing_id = inode->open_passthrough(req);
		if (backing_id) {
			// The kernel now services read/write directly against
			// the memfd. Passthrough is mutually exclusive with
			// FOPEN_DIRECT_IO and owns cache coherency itself, so
			// just drop the stale page cache on open and set no
			// other I/O flags.
			fi->backing_id = backing_id;
			fi->keep_cache = 0;
			return;
		}
		// Passthrough unavailable for this inode; fall through to the
		// daemon-served read/write path below.
	}

	if (memfs_cfg.fuse_dio) {
		// parallel_direct_writes only takes effect alongside direct_io
		fi->direct_io = 1;
		fi->parallel_direct_writes = 1;
	} else if (memfs_cfg.keep_cache) {
		// memfs is the only writer of its data, so cached pages can never
		// go stale behind the kernel's back. FOPEN_KEEP_CACHE keeps cached
		// data across opens instead of invalidating it on close.
		fi->keep_cache = 1;
	}
	// Advertise FOPEN_PARALLEL_DIRECT_WRITES independently of direct_io: a
	// no-op on stock kernels unless FOPEN_DIRECT_IO is also set, but the
	// force-DIO latch can switch a contended inode to shared-lock parallel
	// writes without the server having requested direct_io.
	if (memfs_cfg.parallel_direct_writes)
		fi->parallel_direct_writes = 1;
}

static void memfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
			 mode_t mode, struct fuse_file_info *fi)
{
	auto parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	if (parentInode->find_child(name)) {
		fuse_reply_err(req, EEXIST);
		return;
	}

	auto new_inode = Inodes.create(name, false, mode);
	if (!new_inode) {
		fuse_reply_err(req, EIO);
		return;
	}

	// Create a new Dentry and add it to the parent
	Dentry *new_dentry = new Dentry(name, new_inode);

	//std::cout << "Debug: Created new Dentry at address "
	//	  << (void *)new_dentry << ", name: '" << name
	//	  << "', inode address: " << (void *)new_inode << std::endl;

	int error = parentInode->add_child(name, new_dentry);
	if (error != 0) {
		delete new_dentry;
		Inodes.erase(new_inode.get());
		fuse_reply_err(req, error);
		return;
	}

	struct fuse_entry_param e;
	memset(&e, 0, sizeof(e));
	e.ino = new_inode->get_ino();
	e.attr_timeout = MEMFS_ATTR_TIMEOUT;
	e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
	new_inode->get_attr(&e.attr);

	memfs_setup_file_open(req, new_inode.get(), fi);
	if (memfs_cfg.notify_inval)
		open_files.add(new_inode->get_ino());
	fuse_reply_create(req, &e, fi);
}

static void memfs_write(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
			const char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
	memfs_log_io("WRITE", ino, offset, size);

	// fi->fh carries the Inode* cached at open/create time, so the write hot
	// path never touches the global Inodes lookup or its shared_mutex.
	auto *inode = reinterpret_cast<Inode *>(fi->fh);
	if (!inode) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	if (inode->is_dir()) {
		fuse_reply_err(req, EISDIR);
		return;
	}

	// HANDLE_KILLPRIV_V2: a foreground write drops suid/sgid. The kernel
	// requests this per-write via FUSE_WRITE_KILL_SUIDGID, but libfuse does
	// not surface write_flags to this handler, so approximate by always
	// dropping; the only divergence is a CAP_FSETID writer, whose suid
	// would survive on a local fs. Writeback flushes (fi->writepage) never
	// kill: the kernel settled privileges when the pages were dirtied.
	if (!fi->writepage)
		inode->kill_suidgid();

	if (memfs_cfg.null_io) {
		if (offset < 0) {
			fuse_reply_err(req, EINVAL);
			return;
		}
		// touch every byte so the data transfer is real, then discard
		unsigned char acc = 0;
		for (size_t i = 0; i < size; i++)
			acc ^= (unsigned char)buf[i];
		null_io_write_sink = acc;
		// Record the size even though the data is dropped, otherwise the
		// file stays 0 bytes and readers hit EOF immediately.
		inode->grow_size(offset + (off_t)size);
		fuse_reply_write(req, size);
		return;
	}

	if (offset < 0) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	// pwrite() the memfd; writing past EOF extends it, and it surfaces
	// ENOSPC/EFBIG through errno, so no manual bounds check is needed. This
	// path only runs with passthrough disabled — when it is on the kernel
	// writes the backing memfd itself and WRITE never reaches the daemon.
	ssize_t n = inode->write_content(buf, size, offset);
	if (n < 0) {
		fuse_reply_err(req, errno);
		return;
	}
	fuse_reply_write(req, n);
}

static void memfs_read(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
		       size_t size, off_t offset, struct fuse_file_info *fi)
{
	memfs_log_io("READ", ino, offset, size);

	// Same as memfs_write: dereference the cached Inode* from fi->fh instead
	// of re-resolving through the global Inodes lock on every read.
	auto *inode = reinterpret_cast<Inode *>(fi->fh);
	if (!inode || inode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	if (memfs_cfg.null_io) {
		// Serve arbitrary bytes straight from the pre-filled static
		// buffer when the whole read fits in it (the common case) -- no
		// per-read allocation or fill. Larger reads fall back to a
		// reused per-thread buffer tiled from the same source bytes.
		if (size <= null_io_buf.size()) {
			fuse_reply_buf(req, null_io_buf.data(), size);
			return;
		}
		thread_local std::vector<char> content;
		if (content.size() < size)
			content.resize(size);
		null_io_fill(content.data(), size);
		fuse_reply_buf(req, content.data(), size);
		return;
	}

	if (offset < 0) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	// pread() the memfd; a read at or past EOF returns 0 bytes. Like the
	// write path this only runs with passthrough disabled — otherwise the
	// kernel reads the backing memfd directly and READ never reaches here.
	std::vector<char> content(size);
	ssize_t n = inode->read_content(content.data(), size, offset);
	if (n < 0) {
		fuse_reply_err(req, errno);
		return;
	}
	fuse_reply_buf(req, content.data(), n);
}

static void memfs_open(fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi)
{
	auto inode_data = Inodes.find(ino);
	if (!inode_data || inode_data->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	// FUSE_CAP_ATOMIC_O_TRUNC is negotiated by default, so the kernel folds
	// an O_TRUNC open into this OPEN instead of sending a separate SETATTR;
	// perform the truncation here (this both keeps O_TRUNC correct and
	// saves that extra round-trip).
	if (fi->flags & O_TRUNC) {
		int err = inode_data->truncate(0);
		if (err) {
			fuse_reply_err(req, err);
			return;
		}
		// HANDLE_KILLPRIV_V2: truncation drops suid/sgid. The kernel
		// flags this via FUSE_OPEN_KILL_SUIDGID in fuse_open_in::
		// open_flags, which libfuse does not surface; approximate by
		// always dropping (same CAP_FSETID caveat as memfs_write()).
		inode_data->kill_suidgid();
	}

	memfs_setup_file_open(req, inode_data.get(), fi);
	if (memfs_cfg.notify_inval)
		open_files.add(inode_data->get_ino());
	fuse_reply_open(req, fi);
}

static void memfs_opendir(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	auto inode = Inodes.find(ino);
	if (!inode || !inode->is_dir()) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	// Create a new DirHandle
	auto dir_handle = new DirHandle(inode->get_children());

	// Store the pointer to the DirHandle in fi->fh
	fi->fh = reinterpret_cast<uint64_t>(dir_handle);

	fuse_reply_open(req, fi);
}

// Shared readdir/readdirplus worker. opendir() snapshotted the directory's
// (name, inode) pairs into the DirHandle, so both flavours just walk that
// snapshot by offset. Plain readdir only needs st_ino and the S_IFMT type
// bits, so it fills just those and skips the full get_attr() -- an fstat() on
// the memfd plus the attr lock -- that readdirplus has to pay to return
// complete attributes.
static void memfs_do_readdir(fuse_req_t req, size_t size, off_t offset,
			     struct fuse_file_info *fi, bool plus)
{
	auto *dir_handle = reinterpret_cast<DirHandle *>(fi->fh);
	if (!dir_handle) {
		fuse_reply_err(req, EBADF);
		return;
	}

	// Reuse a per-thread scratch buffer instead of malloc/free-ing one on
	// every request; it only ever grows to the largest readdir size seen.
	thread_local std::vector<char> buffer;
	if (buffer.size() < size)
		buffer.resize(size);

	size_t buf_size = 0;
	for (off_t i = offset;
	     i < static_cast<off_t>(dir_handle->entries.size()); ++i) {
		const auto &entry = dir_handle->entries[i];
		const std::string &name = entry.first;
		const std::shared_ptr<Inode> &inode = entry.second;

		size_t entry_size;
		if (plus) {
			struct fuse_entry_param e;
			memset(&e, 0, sizeof(e));
			e.ino = inode->get_ino();
			e.attr_timeout = MEMFS_ATTR_TIMEOUT;
			e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
			inode->get_attr(&e.attr);
			entry_size = fuse_add_direntry_plus(
				req, buffer.data() + buf_size, size - buf_size,
				name.c_str(), &e, i + 1);
		} else {
			struct stat stbuf;
			memset(&stbuf, 0, sizeof(stbuf));
			stbuf.st_ino = inode->get_ino();
			stbuf.st_mode = inode->get_mode();
			entry_size = fuse_add_direntry(
				req, buffer.data() + buf_size, size - buf_size,
				name.c_str(), &stbuf, i + 1);
		}

		// fuse_add_direntry[_plus]() returns the space the entry needs
		// and writes nothing when it does not fit, so stop here without
		// having committed it.
		if (buf_size + entry_size > size)
			break;
		// readdirplus hands the kernel a lookup reference for every
		// entry it returns (balanced by a later FORGET), exactly as an
		// explicit lookup() would; only count it once the entry has
		// actually made it into the reply buffer.
		if (plus)
			inode->inc_lookup();
		buf_size += entry_size;
	}

	fuse_reply_buf(req, buffer.data(), buf_size);
}

static void memfs_readdir(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
			  size_t size, off_t offset, struct fuse_file_info *fi)
{
	memfs_do_readdir(req, size, offset, fi, false);
}

static void memfs_readdirplus(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
			      size_t size, off_t offset,
			      struct fuse_file_info *fi)
{
	memfs_do_readdir(req, size, offset, fi, true);
}

static void memfs_release(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	auto *inode = reinterpret_cast<Inode *>(fi->fh);

	// This handle is going away: stop offering the file to the background
	// invalidator (its refcount drops, and the inode leaves the set once the
	// last handle is released).
	if (memfs_cfg.notify_inval && inode)
		open_files.remove(inode->get_ino());

	// Drop this open's passthrough reference; the last release of the inode
	// tears down the shared backing registration (see close_passthrough).
	// The memfd itself lives on until the inode is reclaimed.
	if (memfs_cfg.passthrough && inode)
		inode->close_passthrough(req);

	fuse_reply_err(req, 0);
}

static void memfs_releasedir(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	auto *dir_handle = reinterpret_cast<DirHandle *>(fi->fh);
	delete dir_handle;
	fuse_reply_err(req, 0);
}

// Largest write size the running kernel will actually honor. The kernel clamps
// the negotiated max_pages to /proc/sys/fs/fuse/max_pages_limit (a u16 field),
// so asking for more is silently capped -- and libfuse sizes every io-uring
// payload buffer to max_write, i.e. nr_queues(=nproc) * io_uring_q_depth *
// max_write bytes of pinned NUMA memory (see lib/fuse_uring.c), so
// over-requesting just wastes RAM. Read the live ceiling and request exactly it.
static unsigned memfs_max_write_ceiling(void)
{
	unsigned pages = 0;
	FILE *f = fopen("/proc/sys/fs/fuse/max_pages_limit", "re");
	if (f) {
		if (fscanf(f, "%u", &pages) != 1)
			pages = 0;
		fclose(f);
	}
	if (pages == 0)
		pages = 256; // libfuse's stock default; safe fallback
	if (pages > 65535)
		pages = 65535; // fuse_init_out.max_pages is u16
	return pages * (unsigned)getpagesize();
}

static void memfs_init(void *userdata, struct fuse_conn_info *conn)
{
	(void)userdata;

	// Enable read/write passthrough so the kernel serves I/O directly from
	// each file's memfd. If the kernel can't do it, fall back to daemon-
	// served read/write by clearing the flag for the rest of the mount.
	if (memfs_cfg.passthrough &&
	    !fuse_set_feature_flag(conn, FUSE_CAP_PASSTHROUGH)) {
		fuse_log(FUSE_LOG_WARNING,
			 "memfs: kernel does not support FUSE passthrough, "
			 "falling back to daemon-served I/O\n");
		memfs_cfg.passthrough = 0;
	}

	// Passthrough and the writeback cache are mutually exclusive modes; only
	// turn writeback on when passthrough is not in effect.
	if (memfs_cfg.writeback_cache && !memfs_cfg.passthrough)
		fuse_set_feature_flag(conn, FUSE_CAP_WRITEBACK_CACHE);

	// Let the kernel issue lookups (and other directory operations) for the
	// same directory in parallel instead of serializing them under its
	// per-directory lock. libfuse does not enable this by default, so opt
	// in here: memfs does its own fine-grained per-inode locking and
	// lookups now take only a shared lock, so a hot directory scales across
	// cores.
	fuse_set_feature_flag(conn, FUSE_CAP_PARALLEL_DIROPS);

	// Take over suid/sgid stripping (HANDLE_KILLPRIV_V2). Without this the
	// kernel probes GETXATTR "security.capability" before every buffered
	// write: fuse only sets SB_NOSEC under this capability, and without
	// SB_NOSEC the "nothing to strip" result is never cached in S_NOSEC,
	// so the probe repeats per write() instead of running once per inode.
	// The contract this accepts is implemented in Inode::kill_suidgid()
	// and its callers (open/write/setattr).
	fuse_set_feature_flag(conn, FUSE_CAP_HANDLE_KILLPRIV_V2);

	// Deepen the read pipeline so a single sequential reader does not stall
	// one folio at a time waiting for each FUSE READ round-trip. Without
	// this the kernel caps in-flight readahead at libfuse's default
	// max_background (12) and throttles at congestion_threshold (9).
	conn->max_background = memfs_cfg.max_background ?
		memfs_cfg.max_background : MEMFS_DEFAULT_MAX_BACKGROUND;
	// 0 lets fuse_lowlevel derive 3/4 * max_background automatically.
	conn->congestion_threshold = memfs_cfg.congestion_threshold;
	// max_readahead has already been clamped down to the kernel's offered
	// value; raise the negotiated window so readahead can run further ahead.
	if (memfs_cfg.max_readahead)
		conn->max_readahead = memfs_cfg.max_readahead;
	else if (conn->max_readahead < MEMFS_DEFAULT_MAX_READAHEAD)
		conn->max_readahead = MEMFS_DEFAULT_MAX_READAHEAD;

	// Negotiate the largest FUSE_WRITE the kernel will honor. libfuse derives
	// max_pages = ceil(max_write / PAGE_SIZE) from this and sets FUSE_MAX_PAGES
	// (fuse_lowlevel.c do_init). Bigger requests mean fewer, larger writeback
	// requests and larger folios -> less per-MB CPU on the single flusher
	// thread that bottlenecks the write cache. 0 (default) auto-selects the
	// kernel ceiling; override with -o max_write=N. NOTE: with -o io_uring this
	// pins nproc * io_uring_q_depth * max_write bytes of buffers.
	{
		unsigned page = (unsigned)getpagesize();
		unsigned mw = memfs_cfg.max_write ?
			memfs_cfg.max_write : memfs_max_write_ceiling();
		if (mw > 65535u * page) // fuse_init_out.max_pages is u16
			mw = 65535u * page;
		conn->max_write = mw;
	}
}

static void memfs_panic(std::string_view message)
{
	std::cerr << "MEMFS PANIC: " << message << std::endl;
	std::abort();
}

static void memfs_forget_one(fuse_ino_t ino, uint64_t nlookup)
{
	auto inode = Inodes.find(ino);
	if (!inode)
		return;

	uint64_t remaining = inode->dec_lookup(nlookup);

	/* An inode can be reclaimed only once the kernel has dropped all of its
	 * references (nlookup == 0) AND it is no longer linked into any
	 * directory (nlink == 0). Both conditions matter:
	 *
	 *  - A still-linked inode must stay in the global map even when
	 *    forgotten, because that map is the ino -> Inode index that
	 *    getattr()/open()/setattr() resolve through, and lookup() does not
	 *    re-insert it. Erasing it would break a later open-by-ino.
	 *
	 *  - An unlinked but still-open inode keeps nlookup > 0 until the final
	 *    release (the kernel never forgets an inode with open files), so the
	 *    raw Inode* cached in fi->fh stays valid for the whole open.
	 *
	 * Erasing here drops the map's shared_ptr; the local `inode` holds the
	 * last reference, so the Inode (and its content vector) is freed when it
	 * goes out of scope. This is what reclaims memory across the
	 * create/write/unlink cycle.
	 */
	if (remaining == 0 && inode->get_nlink() == 0)
		Inodes.erase(inode.get());
}

static void memfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	memfs_forget_one(ino, nlookup);
	/* FORGET carries no reply to the kernel; fuse_reply_none() only
	 * releases the request.
	 */
	fuse_reply_none(req);
}

static void memfs_forget_multi(fuse_req_t req, size_t count,
			       struct fuse_forget_data *forgets)
{
	for (size_t i = 0; i < count; i++)
		memfs_forget_one(forgets[i].ino, forgets[i].nlookup);
	fuse_reply_none(req);
}

static void memfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			  int to_set, struct fuse_file_info *fi)
{
	// open()/create() cache the Inode* in fi->fh; a request without fi is
	// path-based, so resolve it through the inode number instead.
	std::shared_ptr<Inode> inode_holder;
	Inode *inode_data;
	if (fi) {
		inode_data = reinterpret_cast<Inode *>(fi->fh);
		if (!inode_data) {
			fuse_reply_err(req, EBADF);
			return;
		}
	} else {
		inode_holder = Inodes.find(ino);
		if (!inode_holder) {
			fuse_reply_err(req, ENOENT);
			return;
		}
		inode_data = inode_holder.get();
	}

	if (to_set & FUSE_SET_ATTR_MODE)
		inode_data->set_mode(attr->st_mode);
	if (to_set & FUSE_SET_ATTR_UID)
		inode_data->set_uid(attr->st_uid);
	if (to_set & FUSE_SET_ATTR_GID)
		inode_data->set_gid(attr->st_gid);
	if (to_set & FUSE_SET_ATTR_SIZE) {
		int err = inode_data->truncate(attr->st_size);
		if (err) {
			fuse_reply_err(req, err);
			return;
		}
	}

	// HANDLE_KILLPRIV_V2: FUSE_SET_ATTR_KILL_SUID is the kernel's
	// FATTR_KILL_SUIDGID (sent with killpriv_v2 truncates); chown must
	// drop the bits on its own -- with killpriv_v2 negotiated the kernel
	// no longer folds the kill into the request, a local chown always
	// drops them (even for root), and memfs owns that now.
	if (to_set & (FUSE_SET_ATTR_KILL_SUID | FUSE_SET_ATTR_KILL_SGID |
		      FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID))
		inode_data->kill_suidgid();
	if (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
		// Translate the SETATTR flags into futimens()-style timespecs:
		// UTIME_OMIT for a timestamp that is not being set, UTIME_NOW for
		// the kernel's "..._NOW" (set to current time) requests.
		struct timespec atime = { 0, UTIME_OMIT };
		struct timespec mtime = { 0, UTIME_OMIT };
		if (to_set & FUSE_SET_ATTR_ATIME_NOW)
			atime.tv_nsec = UTIME_NOW;
		else if (to_set & FUSE_SET_ATTR_ATIME)
			atime = attr->st_atim;
		if (to_set & FUSE_SET_ATTR_MTIME_NOW)
			mtime.tv_nsec = UTIME_NOW;
		else if (to_set & FUSE_SET_ATTR_MTIME)
			mtime = attr->st_mtim;
		inode_data->set_times(atime, mtime);
	}

	struct stat st;
	inode_data->get_attr(&st);

	fuse_reply_attr(req, &st, MEMFS_ATTR_TIMEOUT);
}

static void memfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
			mode_t mode, dev_t rdev)
{
	auto parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	if (parentInode->find_child(name)) {
		fuse_reply_err(req, EEXIST);
		return;
	}

	// mode already carries the type bits (S_IFREG/S_IFIFO/S_IFCHR/...)
	auto new_inode = Inodes.create(name, false, mode);
	if (!new_inode) {
		fuse_reply_err(req, EIO);
		return;
	}
	new_inode->set_rdev(rdev);

	Dentry *new_dentry = new Dentry(name, new_inode);
	int error = parentInode->add_child(name, new_dentry);
	if (error != 0) {
		delete new_dentry;
		Inodes.erase(new_inode.get());
		fuse_reply_err(req, error);
		return;
	}

	struct fuse_entry_param e;
	memset(&e, 0, sizeof(e));
	e.ino = new_inode->get_ino();
	e.attr_timeout = MEMFS_ATTR_TIMEOUT;
	e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
	new_inode->get_attr(&e.attr);

	fuse_reply_entry(req, &e);
}

static void memfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
			mode_t mode)
{
	int error = 0;
	std::shared_ptr<Inode> parentInode = nullptr;
	std::shared_ptr<Inode> new_inode = nullptr;
	Dentry *new_dentry = nullptr;
	struct fuse_entry_param e;

	parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		error = ENOENT;
		goto out;
	}

	new_inode = Inodes.create(name, true, mode | S_IFDIR);
	if (!new_inode) {
		error = EIO;
		goto out;
	}

	new_dentry = new Dentry(name, new_inode);
	error = parentInode->add_child(name, new_dentry);
	if (error != 0) {
		goto out_cleanup;
	}

	memset(&e, 0, sizeof(e));
	e.ino = new_inode->get_ino();
	e.attr_timeout = MEMFS_ATTR_TIMEOUT;
	e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
	new_inode->get_attr(&e.attr);

out:
	if (error == 0) {
		fuse_reply_entry(req, &e);
	} else {
		fuse_reply_err(req, error);
	}
	return;

out_cleanup:
	delete new_dentry;
	Inodes.erase(new_inode.get());
	goto out;
}

static void memfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	auto parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	parentInode->lock();

	auto child_dentry = parentInode->find_child_locked(name);
	if (child_dentry == nullptr) {
		parentInode->unlock();
		fuse_reply_err(req, ENOENT);
		return;
	}

	Inode *child = child_dentry->get_inode();
	if (!child || !child->is_dir() || !child->is_empty()) {
		parentInode->unlock();
		fuse_reply_err(req, child ? (child->is_empty() ? ENOTDIR :
								 ENOTEMPTY) :
					    ENOENT);
		return;
	}

	parentInode->remove_child(name);
	// An empty directory has nlink == 2 (its own "." and the parent's
	// entry). remove_child() already dropped the parent's ".." link to it;
	// drop both of the directory's own links so nlink reaches 0 and the
	// inode becomes reclaimable on the following FORGET (see
	// memfs_forget_one).
	child->dec_nlink();
	child->dec_nlink();

	parentInode->unlock();

	fuse_reply_err(req, 0);
}

static void memfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	auto parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	parentInode->lock();

	auto child_dentry = parentInode->find_child_locked(name);
	if (child_dentry == nullptr) {
		parentInode->unlock();
		fuse_reply_err(req, ENOENT);
		return;
	}

	Inode *child = child_dentry->get_inode();
	if (!child || child->is_dir()) {
		parentInode->unlock();
		fuse_reply_err(req, child ? EISDIR : ENOENT);
		return;
	}

	parentInode->remove_child(name);
	child->dec_nlink();

	parentInode->unlock();

	fuse_reply_err(req, 0);
}

static void memfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
			 fuse_ino_t newparent, const char *newname,
			 unsigned int flags)
{
	int error = 0;
	std::shared_ptr<Inode> parentInode = nullptr;
	std::shared_ptr<Inode> newparentInode = nullptr;
	Dentry *child_dentry = nullptr;
	Dentry *child_dentry_copy = nullptr;
	Dentry *existing_dentry = nullptr;
	Inode *inode_a = nullptr;
	Inode *inode_b = nullptr;

#if defined(RENAME_EXCHANGE) && defined(RENAME_NOREPLACE)
	if (flags & (RENAME_EXCHANGE | RENAME_NOREPLACE)) {
		fuse_reply_err(req, EINVAL);
		return;
	}
#else
	(void)flags;
#endif

	Inodes.lock();

	parentInode = Inodes.find_locked(parent);
	newparentInode = Inodes.find_locked(newparent);
	if (!parentInode || !parentInode->is_dir() || !newparentInode ||
	    !newparentInode->is_dir()) {
		error = ENOENT;
		goto out_unlock_global;
	}

	inode_a = parentInode.get();
	inode_b = (parent != newparent) ? newparentInode.get() : nullptr;
	if (inode_b && inode_a->get_ino() > inode_b->get_ino())
		std::swap(inode_a, inode_b); // always lock lower ino first
	inode_a->lock();
	if (inode_b)
		inode_b->lock();

	child_dentry = parentInode->find_child_locked(name);
	if (child_dentry == nullptr) {
		error = ENOENT;
		goto out_unlock;
	}

	existing_dentry = newparentInode->find_child_locked(newname);
	if (existing_dentry) {
		Inode *existing_inode = existing_dentry->get_inode();
		if (existing_inode->is_dir() && !existing_inode->is_empty()) {
			error = ENOTEMPTY;
			goto out_unlock;
		}
		// remove_child() frees the dentry and already decrements
		// newparent's nlink for a dir child; resolve the inode first.
		newparentInode->remove_child(newname);
		existing_inode->dec_nlink();
		// An overwritten empty directory, like in rmdir, must also drop
		// its own "." link so nlink reaches 0 and it is reclaimed on the
		// next FORGET.
		if (existing_inode->is_dir())
			existing_inode->dec_nlink();
	}

	child_dentry_copy = new Dentry(newname, child_dentry->inode);
	parentInode->remove_child(name);
	newparentInode->add_child_locked(newname, child_dentry_copy);

out_unlock:
	if (inode_b)
		inode_b->unlock();
	inode_a->unlock();

out_unlock_global:
	Inodes.unlock();
	fuse_reply_err(req, error);
}

static void memfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
		       const char *newname)
{
	int error = 0;
	std::shared_ptr<Inode> src_inode = nullptr;
	std::shared_ptr<Inode> parent_inode = nullptr;
	struct fuse_entry_param e;
	Dentry *new_dentry = nullptr;

	Inodes.lock();

	src_inode = Inodes.find_locked(ino);
	if (!src_inode) {
		error = ENOENT;
		goto out_unlock_global;
	}

	parent_inode = Inodes.find_locked(newparent);
	if (!parent_inode || !parent_inode->is_dir()) {
		error = ENOENT;
		goto out_unlock_global;
	}

	parent_inode->lock();

	// Check if the new name already exists in the parent directory
	if (parent_inode->find_child_locked(newname) != nullptr) {
		error = EEXIST;
		goto out_unlock_parent;
	}

	src_inode->inc_nlink();

	new_dentry = new Dentry(newname, src_inode);
	error = parent_inode->add_child_locked(newname, new_dentry);
	if (error != 0) {
		delete new_dentry;
		src_inode->dec_nlink();
		goto out_unlock_parent;
	}

	// the reply below hands the kernel a new lookup reference
	src_inode->inc_lookup();

	memset(&e, 0, sizeof(e));
	e.ino = ino;
	e.attr_timeout = MEMFS_ATTR_TIMEOUT;
	e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
	src_inode->get_attr(&e.attr);

out_unlock_parent:
	parent_inode->unlock();

out_unlock_global:
	Inodes.unlock();

	if (error == 0) {
		fuse_reply_entry(req, &e);
	} else {
		fuse_reply_err(req, error);
	}
}

static void memfs_statfs(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino)
{
	struct statvfs stbuf;
	memset(&stbuf, 0, sizeof(stbuf));

	stbuf.f_bsize = 4096;
	stbuf.f_frsize = 4096;
	stbuf.f_namemax = PATH_MAX; // Maximum filename length

	stbuf.f_files = Inodes.size(); // Total inodes (files + directories)

	stbuf.f_ffree = std::numeric_limits<fsfilcnt_t>::max() -
			stbuf.f_files; // Free inodes

	// Set total and free blocks
	// For simplicity, we'll set a fixed total number of blocks and calculate free blocks based on used inodes
	stbuf.f_blocks = 1000000; // arbitrary number, needs to be a parameter
	stbuf.f_bfree = stbuf.f_blocks -
			(stbuf.f_files *
			 10); // Assume each file uses 10 blocks on average
	stbuf.f_bavail = stbuf.f_bfree;

	stbuf.f_fsid = 0;

	// Set flags
	stbuf.f_flag = ST_NOSUID;

	fuse_reply_statfs(req, &stbuf);
}

static void memfs_dlm_lock(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
			   [[maybe_unused]] uint64_t start,
			   [[maybe_unused]] uint64_t end,
			   [[maybe_unused]] uint32_t type,
			   [[maybe_unused]] struct fuse_file_info *fi)
{
	memfs_log_dlm(ino, start, end, type);

	/* memfs is an in-memory, single-host filesystem, so there is no real
	 * distributed lock manager to consult and no conflicting clients to
	 * arbitrate against. Mirror passthrough_hp and simply grant the whole
	 * requested range.
	 */
	fuse_reply_dlm_lock(req, start, UINT64_MAX - 1);
}

#ifdef HAVE_STATX
static void stat_to_statx(const struct stat *st, struct statx *stx)
{
	memset(stx, 0, sizeof(*stx));

	/* We only ever have the basic-stat fields available in memory. */
	stx->stx_mask = STATX_BASIC_STATS;
	stx->stx_blksize = 4096;
	stx->stx_nlink = st->st_nlink;
	stx->stx_uid = st->st_uid;
	stx->stx_gid = st->st_gid;
	stx->stx_mode = st->st_mode;
	stx->stx_ino = st->st_ino;
	stx->stx_size = st->st_size;
	stx->stx_blocks = st->st_blocks;

	stx->stx_atime.tv_sec = st->st_atime;
	stx->stx_ctime.tv_sec = st->st_ctime;
	stx->stx_mtime.tv_sec = st->st_mtime;

	stx->stx_rdev_major = major(st->st_rdev);
	stx->stx_rdev_minor = minor(st->st_rdev);
}

static void memfs_statx(fuse_req_t req, fuse_ino_t ino,
			[[maybe_unused]] int flags, [[maybe_unused]] int mask,
			struct fuse_file_info *fi)
{
	// open()/create() cache the Inode* in fi->fh; a request without fi is
	// path-based, so resolve it through the inode number instead.
	std::shared_ptr<Inode> inode_holder;
	Inode *inode_data;
	if (fi) {
		inode_data = reinterpret_cast<Inode *>(fi->fh);
		if (!inode_data) {
			fuse_reply_err(req, EBADF);
			return;
		}
	} else {
		inode_holder = Inodes.find(ino);
		if (!inode_holder) {
			fuse_reply_err(req, ENOENT);
			return;
		}
		inode_data = inode_holder.get();
	}

	struct stat stbuf;
	inode_data->get_attr(&stbuf);

	struct statx stxbuf;
	stat_to_statx(&stbuf, &stxbuf);

	fuse_reply_statx(req, 0, &stxbuf, MEMFS_ATTR_TIMEOUT);
}
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static const struct fuse_lowlevel_ops memfs_oper = {
	.init = memfs_init,
	.lookup = memfs_lookup,
	.forget = memfs_forget,
	.getattr = memfs_getattr,
	.setattr = memfs_setattr,
	.mknod = memfs_mknod,
	.mkdir = memfs_mkdir,
	.unlink = memfs_unlink,
	.rmdir = memfs_rmdir,
	.rename = memfs_rename,
	.link = memfs_link,
	.open = memfs_open,
	.read = memfs_read,
	.write = memfs_write,
	.release = memfs_release,
	.opendir = memfs_opendir,
	.readdir = memfs_readdir,
	.releasedir = memfs_releasedir,
	.statfs = memfs_statfs,
	.create = memfs_create,
	.forget_multi = memfs_forget_multi,
	.readdirplus = memfs_readdirplus,
#ifdef HAVE_STATX
	.statx = memfs_statx,
#endif
	.dlm_lock = memfs_dlm_lock,
	.lookupx = memfs_lookupx,
};
#pragma GCC diagnostic pop

// Background cache-invalidation thread (enabled with -o notify_inval). It
// simulates redfs peers mutating files on other nodes: at randomized intervals
// it fires a storm of FUSE_NOTIFY_INVAL_INODE messages, each asking the kernel
// to drop the cached pages and/or attributes of a randomly picked open file.
static std::mutex notify_lock;
static std::condition_variable notify_cv;
static std::atomic<bool> notify_stop;
static std::thread notify_thread;

// Fire one storm of up to `count` back-to-back invalidations, each aimed at a
// randomly chosen open file (with replacement, so a file can be hit several
// times per storm). Called without notify_lock held: with the writeback cache
// enabled every notify_inval_inode() can block on pending writeback, and
// stop/join must not stall behind the storm -- notify_stop is polled between
// messages instead.
static void memfs_notify_storm(struct fuse_session *se, std::mt19937 &rng,
			       unsigned count)
{
	for (unsigned i = 0; i < count && !notify_stop; i++) {
		fuse_ino_t ino = open_files.pick_random(rng);
		if (ino == 0)
			break;

		// Randomly invalidate just the attributes (off < 0) or the
		// whole page cache plus attributes (off == 0).
		off_t off = (rng() & 1) ? -1 : 0;
		int ret = fuse_lowlevel_notify_inval_inode(se, ino, off, 0);
		if (ret == 0) {
			memfs_log_notify(ino, off);
			continue;
		}

		// ENODEV means the mount is gone and ENOSYS a pre-7.12 kernel:
		// every further message would fail the same way, so abort the
		// whole storm. ENOENT/EBADF only mean the kernel has already
		// dropped this inode (expected around unmount) -- another
		// victim may still be cached, so keep going. Nothing is fatal
		// for a simulation; just log the unexpected.
		if (ret == -ENODEV || ret == -ENOSYS)
			break;
		if (ret != -ENOENT && ret != -EBADF)
			fuse_log(FUSE_LOG_WARNING,
				 "memfs: notify_inval_inode(ino=%ju) failed: %s\n",
				 (uintmax_t)ino, strerror(-ret));
	}
}

static void memfs_notify_loop(struct fuse_session *se)
{
	std::mt19937 rng(std::random_device{}());
	unsigned base = memfs_cfg.notify_interval_ms ?
				memfs_cfg.notify_interval_ms :
				MEMFS_DEFAULT_NOTIFY_INTERVAL_MS;
	unsigned storm = memfs_cfg.notify_storm ? memfs_cfg.notify_storm :
						  MEMFS_DEFAULT_NOTIFY_STORM;

	std::unique_lock<std::mutex> lock(notify_lock);
	while (!notify_stop) {
		// Sleep a random slice of [base/2, base] ms so the storms do
		// not land on a fixed cadence. Waiting on the condition variable
		// lets memfs_stop_notify() cut the sleep short at unmount.
		std::uniform_int_distribution<unsigned> delay(base / 2 + 1, base);
		if (notify_cv.wait_for(lock,
				       std::chrono::milliseconds(delay(rng)),
				       [] { return notify_stop.load(); }))
			break;

		// Drop notify_lock while calling into libfuse so that
		// memfs_stop_notify() can set notify_stop at any time -- the
		// storm polls it between messages (see memfs_notify_storm).
		lock.unlock();
		memfs_notify_storm(se, rng, storm);
		lock.lock();
	}
}

static void memfs_start_notify(struct fuse_session *se)
{
	if (!memfs_cfg.notify_inval)
		return;
	notify_thread = std::thread(memfs_notify_loop, se);
}

static void memfs_stop_notify(void)
{
	if (!notify_thread.joinable())
		return;
	{
		std::lock_guard<std::mutex> lock(notify_lock);
		notify_stop = true;
	}
	notify_cv.notify_all();
	notify_thread.join();
}

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	int ret = -1;
	struct fuse_loop_config *config = fuse_loop_cfg_create();

	if (config == NULL) {
		std::cerr << "fuse_loop_cfg_create failed" << std::endl;
		exit(EXIT_FAILURE);
	}

	// Passthrough is the default; -o no_passthrough opts out. The kernel
	// negotiation happens in memfs_init(), which clears this if unsupported.
	memfs_cfg.passthrough = 1;

	if (fuse_opt_parse(&args, &memfs_cfg, memfs_opt_spec, NULL) != 0)
		return 1;

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_help) {
		printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
		printf("File-system specific options:\n"
		       "    -o opt,[opt...]        mount options\n"
		       "    -o no_passthrough      do not hand each file's memfd to\n"
		       "                           the kernel as a passthrough backing\n"
		       "                           file (passthrough is on by default;\n"
		       "                           it serves read/write in-kernel)\n"
		       "    -o null_io             bypass the content store for\n"
		       "                           read/write benchmarking (disables\n"
		       "                           passthrough)\n"
		       "    -o fuse_dio            enable direct I/O and parallel\n"
		       "                           direct writes (disables passthrough)\n"
		       "    -o writeback_cache     enable the kernel writeback cache\n"
		       "    -o parallel_direct_writes  set FOPEN_PARALLEL_DIRECT_WRITES\n"
		       "                           (shared inode lock for DIO writes;\n"
		       "                           no-op on stock kernels without\n"
		       "                           direct_io)\n"
		       "    -o keep_cache          set FOPEN_KEEP_CACHE so the kernel\n"
		       "                           keeps cached file data across opens\n"
		       "    -o debug_io            log every read/write (offset,\n"
		       "                           size, end) to stderr with a\n"
		       "                           timestamp\n"
		       "    -o max_background=N    max in-flight readahead/async\n"
		       "                           requests (default 64)\n"
		       "    -o congestion_threshold=N  readahead throttle point\n"
		       "                           (default 3/4 of max_background)\n"
		       "    -o max_readahead=N     negotiated readahead window in\n"
		       "                           bytes (default 4 MiB)\n"
		       "    -o max_write=N         negotiated max FUSE_WRITE size in\n"
		       "                           bytes (default: kernel ceiling from\n"
		       "                           /proc/sys/fs/fuse/max_pages_limit)\n"
		       "    -o notify_inval        run a background thread that, at\n"
		       "                           random intervals, fires a storm of\n"
		       "                           kernel cache invalidations at random\n"
		       "                           open files (redfs peer-modification\n"
		       "                           simulation)\n"
		       "    -o notify_interval_ms=N  upper bound on the random delay\n"
		       "                           between storms (default 1000)\n"
		       "    -o notify_storm=N      invalidations fired back-to-back\n"
		       "                           in each storm (default 64)\n"
		       "    -h   --help            print help\n"
		       "\n");
		fuse_cmdline_help();
		fuse_lowlevel_help();
		ret = 0;
		goto err_out1;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err_out1;
	}

	if (opts.mountpoint == NULL) {
		printf("usage: %s [options] <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		ret = 1;
		goto err_out1;
	}

	// Passthrough is the default but conflicts with the other I/O modes, so
	// any explicitly requested mode wins over it: null_io has no memfd to
	// pass through, -o fuse_dio asks for FOPEN_DIRECT_IO, and -o
	// writeback_cache asks for the writeback cache -- all three are mutually
	// exclusive with passthrough. Turn passthrough off if any is set.
	if (memfs_cfg.passthrough &&
	    (memfs_cfg.null_io || memfs_cfg.fuse_dio || memfs_cfg.writeback_cache)) {
		const char *why = memfs_cfg.null_io	 ? "null_io" :
				  memfs_cfg.fuse_dio	 ? "fuse_dio" :
							   "writeback_cache";
		fuse_log(FUSE_LOG_WARNING,
			 "memfs: disabling passthrough (incompatible with %s)\n",
			 why);
		memfs_cfg.passthrough = 0;
	}

	if (memfs_cfg.null_io) {
		null_io_buf.resize(NULL_IO_BUF_SIZE);
		std::mt19937 rng(0);
		for (auto &byte : null_io_buf)
			byte = static_cast<char>(rng());
	}

	se = fuse_session_new(&args, &memfs_oper, sizeof(memfs_oper), NULL);
	if (se == NULL)
		goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
		goto err_out2;

	if (fuse_session_mount(se, opts.mountpoint) != 0)
		goto err_out3;

	fuse_daemonize(opts.foreground);

	// Start the background invalidator after daemonize() so it runs in the
	// final (post-fork) process, and stop it before the session is torn down
	// since it calls into se.
	memfs_start_notify(se);

	ret = fuse_session_loop_mt(se, config);

	memfs_stop_notify();

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}
