package ipc

import "golang.org/x/sys/unix"

func sockPeerCred(fd int) (uint32, []uint32, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, nil, err
	}
	return cred.Uid, []uint32{cred.Gid}, nil
}
