# lib/notify.sh - body for the notification / invalidation cases.
#
# Caller sets before sourcing:
#   FS_NAME       example to mount
#   NOTIFY        1 to let the filesystem notify the kernel, 0 for --no-notify
#   NOTIFY_MODE   content | size | entry
#   FS_ARGS       extra arguments, optional
#   MARKER_ABSENT regex the daemon prints when the kernel refuses, optional
#
# Every mode has the same shape: mount, look at the filesystem, wait for the
# filesystem to have moved on, look again. With notification on the kernel must
# have seen the change; with it off the kernel's cache must still be serving
# what it saw first.

notify_args="--update-interval=1"
[ "$NOTIFY" = 1 ] || notify_args="$notify_args --no-notify"

# $FAIL_CALLBACK, for the marker the daemon may still be about to write.
_notify_recheck_marker()
{
	_require_fs_marker_absent "$MARKER_ABSENT"
}

fuse_mount "$FS_NAME" $notify_args ${FS_ARGS:-} >/dev/null

if [ -n "${MARKER_ABSENT:-}" ]; then
	# Not gated here: nothing has been looked up yet, so no example can
	# have tried to notify, and none of them reports on kernel support
	# before it has. $FAIL_CALLBACK is what catches it.
	FAIL_CALLBACK=_notify_recheck_marker
fi

case $NOTIFY_MODE in
content)
	# The file holds a timestamp the filesystem rewrites; notification is
	# what makes the kernel re-read it.
	read1=$(cat "$TEST_MNT/current_time")
	sleep 2
	read2=$(cat "$TEST_MNT/current_time")
	if [ "$NOTIFY" = 1 ]; then
		_assert_ne "$read1" "$read2" "content did not change"
	else
		_assert_eq "$read1" "$read2" "cached content changed"
	fi
	;;
size)
	size=$(_check fuse_test_size "$TEST_MNT/growing")
	sleep 2
	new_size=$(_check fuse_test_size "$TEST_MNT/growing")
	if [ "$NOTIFY" = 1 ]; then
		[ "$new_size" -gt "$size" ] ||
			_fail "growing file stayed at $size bytes"
	else
		_assert_eq "$new_size" "$size" "cached size changed"
	fi
	;;
entry)
	fname=$(_check fuse_test_listdir_first "$TEST_MNT")
	if [ ! -e "$TEST_MNT/$fname" ]; then
		# We hit a race and issued readdir just before the name changed.
		fname=$(_check fuse_test_listdir_first "$TEST_MNT")
		[ -e "$TEST_MNT/$fname" ] ||
			_fail "$fname vanished twice in a row"
	fi

	sleep 2
	if [ "$NOTIFY" != 1 ]; then
		# Without notification the entry stays visible until the
		# kernel's own --timeout expires.
		[ -e "$TEST_MNT/$fname" ] ||
			_fail "$fname expired before the entry timeout"
		sleep 5
	fi
	_assert_errno ENOENT fuse_test_stat "$TEST_MNT/$fname"
	;;
*)
	_fail "unknown NOTIFY_MODE '$NOTIFY_MODE'"
	;;
esac

fuse_umount
