#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/time.h>
#include <limits.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/wait.h>

static char *mirror_root = NULL;
static char *backup_root = NULL;
static int encrypt_backups = 0;
static char *enc_key = NULL;

static char *fullpath_for(const char *root, const char *path){
	char buf[PATH_MAX];
	if(snprintf(buf, PATH_MAX, "%s%s", root, path) >= PATH_MAX){
		return NULL;
	}
	return strdup(buf);
}

static int ensure_backup_dir(const char *backup_path){
	char tmp[PATH_MAX];
	strncpy(tmp, backup_path, PATH_MAX - 1);
	tmp[PATH_MAX - 1] = '\0';
	char *dir = dirname(tmp);
	char accum[PATH_MAX] = {0};
	const char *p = dir;

	if(*p == '/'){
		strcpy(accum, "/");
		p++;
	}

	while(*p){
		const char *slash = strchr(p, '/');
		size_t len = slash ? (size_t)(slash - p): strlen(p);
		if(len == 0)
			break;
		if(accum[0] == '\0' && accum[1] == '\0'){}
		if(strlen(accum) + 1 + len + 1 >= PATH_MAX)
			break;
		if(!(strlen(accum) == 1 && accum[0] == '/')){
			strcat(accum, "/");
		}
		strncat(accum,p,len);
		struct stat st;
		if(stat(accum, &st) == -1){
			if(mkdir(accum, 0755) == -1){
				if(errno != EEXIST)
					return -errno;
			}
		}
		if(!slash)
			break;
		p = slash + 1;
	}
	return 0;
}

static int copy_file(const char *src, const char *dst){
	int in_fd = open(src, O_RDONLY);
	if(in_fd < 0)
		return -errno;

	int rc = ensure_backup_dir(dst);
	if(rc < 0){
		close(in_fd);
		return rc;
	}

	int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if(out_fd < 0){
		close(in_fd);
		return -errno;
	}

	struct stat st;
	if(fstat(in_fd, &st) == -1){
		close(in_fd);
		close(out_fd);
		return -errno;
	}

	off_t offset = 0;
	ssize_t sent;
	while(offset < st.st_size){
		sent = sendfile(out_fd, in_fd, &offset, st.st_size - offset);
		if(sent <= 0){
			char buf[8192];
			ssize_t r = read(in_fd, buf, sizeof(buf));
			if(r <= 0)
				break;
			ssize_t w = write(out_fd, buf, r);
			if(w != r)
				break;
		}
	}

	fsync(out_fd);
	close(in_fd);
	close(out_fd);
	return 0;
}

static void copy_to_backup(const char *path){
	if(!backup_root)
		return;

	char *src = fullpath_for(mirror_root, path);
	char *dst_plain = fullpath_for(backup_root, path);
	if(!src || !dst_plain){
		free(src);
		free(dst_plain);
		return;
	}

	int rc = copy_file(src, dst_plain);
	if(rc != 0){
		fprintf(stderr, "backup copy failed for %s: %d\n", dst_plain, rc);
	} else {
		if(encrypt_backups && enc_key){
			char enc_cmd[PATH_MAX * 2 + 256];
			snprintf(enc_cmd, sizeof(enc_cmd), "openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:%s -in '%s' -out'%s.enc' 2>/dev/null && rm -f '%s'", enc_key, dst_plain, dst_plain, dst_plain);
			int r = system(enc_cmd);
			(void)r;
		}
	}
	free(src);
	free(dst_plain);
}

static void path_to_real(const char *path, char *out, size_t outsz){
	if(snprintf(out, outsz, "%s%s", mirror_root, path) >= (int)outsz){
		out[0] = '\0';
	}
}

static int b_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi){
	(void) fi;
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	int res = lstat(real, stbuf);
	if(res == -1)
		return -errno;
	return 0;
}

static int b_access(const char *path, int mask){
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	int res = access(real, mask);
	if(res == -1)
		return -errno;
	return 0;
}

static int b_readlink(const char *path, char *buf, size_t buflen){
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	ssize_t len = readlink(real, buf,buflen - 1);
	if(len == -1)
		return -errno;
	buf[len] = '\0';
	return 0;
}

static int b_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags){
	(void) offset;
	(void) fi;
	(void) flags;
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	DIR *dp = opendir(real);
	if(!dp)
		return -errno;

	struct dirent *de;
	filler(buf, ". ", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	while((de = readdir(dp)) != NULL){
		struct stat st;
		memset(&st, 0, sizeof(st));
		filler(buf, de->d_name, &st, 0, 0);
	}
	closedir(dp);
	return 0;
}

static int b_mkdir(const char *path, mode_t mode){
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	int res = mkdir(real, mode);
	if(res == -1)
		return -errno;
	char *bk = fullpath_for(backup_root, path);
	if(bk){
		ensure_backup_dir(bk);
		mkdir(bk, mode);
		free(bk);
	}
	return 0;
}

static int b_rmdir(const char *path){
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	int res = rmdir(real);
	if(res == -1)
		return -errno;

	char *bk = fullpath_for(backup_root, path);
	if(bk){
		rmdir(bk);
		free(bk);
	}
	return 0;
}

static int b_unlink(const char *path){
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	int res = unlink(real);
	if(res == -1)
		return -errno;

	char *bk = fullpath_for(backup_root, path);
	if(bk){
		unlink(bk);
		free(bk);
	}
	return 0;
}

static int b_rename(const char *from, const char *to, unsigned int flags){
	(void) flags;
	char rf[PATH_MAX], rt[PATH_MAX];
	path_to_real(from, rf, sizeof(rf));
	path_to_real(to, rt, sizeof(rt));
	int res = rename(rf, rt);
	if(res == -1)
		return -errno;

	char *to_rel = strdup(to);
	if(to_rel){
		copy_to_backup(to_rel);
		free(to_rel);
	}
	return 0;
}

static int b_truncate(const char *path, off_t size, struct fuse_file_info *fi){
	(void) fi;
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	int res = truncate(real, size);
	if(res == -1)
		return -errno;
	copy_to_backup(path);
	return 0;
}

static int b_open(const char *path, struct fuse_file_info *fi){
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	int fd = open(real, fi->flags);
	if(fd == -1)
		return -errno;
	fi->fh = fd;
	return 0;
}

static int b_create(const char *path, mode_t mode, struct fuse_file_info *fi){
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	int fd = open(real, fi->flags | O_CREAT, mode);
	if(fd == -1)
		return -errno;
	fi->fh = fd;
	copy_to_backup(path);
	return 0;
}

static int b_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	int fd = (int) fi->fh;
	if(fd == 0){
		char real[PATH_MAX];
		path_to_real(path, real, sizeof(real));
		fd = open(real, O_RDONLY);
		if(fd < 0)
			return -errno;
		ssize_t res = pread(fd, buf, size, offset);
		close(fd);
		if(res == -1)
			return -errno;
		return res;
	}
	ssize_t res = pread(fd, buf, size, offset);
	if(res == -1)
		return -errno;
	return res;
}

static int b_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	int fd = (int) fi->fh;
	if(fd == 0){
		char real[PATH_MAX];
		path_to_real(path, real, sizeof(real));
		fd = open(real, O_WRONLY);
		if(fd < 0)
			return -errno;
		ssize_t res = pwrite(fd, buf, size, offset);
		close(fd);
		if(res == -1)
			return -errno;
		copy_to_backup(path);
		return res;
	}

	ssize_t res = pwrite(fd, buf, size, offset);
	if(res == -1)
		return -errno;
	copy_to_backup(path);
	return res;
}

static int b_release(const char *path, struct fuse_file_info *fi){
	(void) path;
	close((int) fi->fh);
	return 0;
}

static int b_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi){
	(void) fi;
	int res;
	char real[PATH_MAX];
	path_to_real(path, real, sizeof(real));
	struct timeval times[2];
	times[0].tv_sec = tv[0].tv_sec;
	times[0].tv_usec = tv[0].tv_nsec / 1000;
	times[1].tv_sec = tv[1].tv_sec;
	times[1].tv_usec = tv[1].tv_nsec / 1000;
	res = utimes(real, times);
	if(res == -1)
		return -errno;
	return 0;
}

static const struct fuse_operations ops = {
	.getattr = b_getattr,
	.readlink = b_readlink,
	.readdir = b_readdir,
	.mkdir = b_mkdir,
	.rmdir = b_rmdir,
	.unlink = b_unlink,
	.rename = b_rename,
	.truncate = b_truncate,
	.open = b_open,
	.create = b_create,
	.read = b_read,
	.write = b_write,
	.release = b_release,
	.utimens = b_utimens,
	.access = b_access,
};

static int parse_opts(int argc, char *argv[]){
	int i = 1;
	int outi = 1;
	while(i < argc){
		if(strcmp(argv[i], "--mirror") == 0 && i+1 < argc){
			mirror_root = realpath(argv[i+1], NULL);
			i += 2;
		} else if(strcmp(argv[i], "--backup") == 0 && i+1 < argc){
			backup_root = realpath(argv[i+1], NULL);
			i += 2;
		}else if(strcmp(argv[i], "--encrypt-backups") == 0){
			encrypt_backups = 1;
			i++;
		}else if(strcmp(argv[i], "--enc-key") == 0 && i+1 < argc){
			enc_key = strdup(argv[i+1]);
			i += 2;
		}else{
			argv[outi++] = argv[i++];
		}
	}
	return outi;
}

int main(int argc, char *argv[]){
	if(argc < 4){
		fprintf(stderr, "Usage %s --mirror <mirror_root> --backup <backup_root> [--encrypt-backups --enc-key KEY] <mountpoint> [fuse options]\n", argv[0]);
		return 1;
	}
	int new_argc = parse_opts(argc, argv);
	if(!mirror_root || !backup_root){
		fprintf(stderr, "mirror_root and backup_root are required.\n");
		return 1;
	}

	fprintf(stderr, "mirror_root=%s, backup-root=%s, encrypt=%d\n", mirror_root, backup_root, encrypt_backups);

	struct stat st;

	if(stat(backup_root, &st) == -1){
		if(mkdir(backup_root, 0755) == -1){
			perror("mkdir backup_root");
			return 1;
		}
	}

	return fuse_main(new_argc, argv, &ops, NULL);
}



















