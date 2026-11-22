//go:build !linux

package api

import "errors"

func readDiskUsage(string) (diskUsage, error) {
	return diskUsage{}, errors.New("disk space is only measured on Linux")
}
