#include <sys/types.h>
#include <sys/stat.h>
#include <linux/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

#define DEVICE_IOCTL_MAGIC      '1'
 
#define DEVICE_IOCTL_ON         _IO(DEVICE_IOCTL_MAGIC, 0)
#define DEVICE_IOCTL_OFF        _IO(DEVICE_IOCTL_MAGIC, 1)
 
#define DEVICE_IOCTL_READ       _IOR(DEVICE_IOCTL_MAGIC, 2, int)
#define DEVICE_IOCTL_WRITE      _IOW(DEVICE_IOCTL_MAGIC, 3, int)
#define DEVICE_IOCTL_RDWR       _IOWR(DEVICE_IOCTL_MAGIC, 4, int)

#define DEVICE_IOCTL_MAX        5   // 인덱스의 최대 갯수

int main()
{
	int fd;
	int ret;
	char data = 0;


	fd = open("/dev/test", O_RDWR);
	printf("fd : %d\n", fd);
	
	ioctl(fd, DEVICE_IOCTL_READ, &data);
	printf("read ret : %d\n", data);

	data = 20;
	ioctl(fd, DEVICE_IOCTL_WRITE, &data);
	printf("write ret : %d\n", data);
	

	close(fd);
	return 0;
}
