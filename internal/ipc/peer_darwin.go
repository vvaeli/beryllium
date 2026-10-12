package ipc

import "golang.org/x/sys/unix"

func sockPeerCred(fd int) (uint32, []uint32, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, nil, err
	}
	n := max(0, min(int(cred.Ngroups), len(cred.Groups)))
	return cred.Uid, cred.Groups[:n], nil
}
