/* Hold q6voice's CS-Voice PCM open without reading or writing it.
 * The q6voiced proof of concept prepares these control PCMs and then waits.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct snd_pcm_t snd_pcm_t;
typedef int (*open_fn)(snd_pcm_t **, const char *, int, int);
typedef int (*set_fn)(snd_pcm_t *, int, int, unsigned int, unsigned int, int, unsigned int);
typedef int (*prepare_fn)(snd_pcm_t *);
typedef int (*close_fn)(snd_pcm_t *);
typedef const char *(*strerror_fn)(int);
static volatile sig_atomic_t running = 1;
static void stop(int signum) { (void)signum; running = 0; }

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "playback") && strcmp(argv[1], "capture"))) {
        fprintf(stderr, "usage: %s playback|capture\n", argv[0]);
        return 2;
    }
    int stream = strcmp(argv[1], "playback") == 0 ? 0 : 1;
    void *lib = dlopen("libasound.so.2", RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    open_fn snd_pcm_open = (open_fn)dlsym(lib, "snd_pcm_open");
    set_fn snd_pcm_set_params = (set_fn)dlsym(lib, "snd_pcm_set_params");
    prepare_fn snd_pcm_prepare = (prepare_fn)dlsym(lib, "snd_pcm_prepare");
    close_fn snd_pcm_close = (close_fn)dlsym(lib, "snd_pcm_close");
    strerror_fn snd_strerror = (strerror_fn)dlsym(lib, "snd_strerror");
    if (!snd_pcm_open || !snd_pcm_set_params || !snd_pcm_prepare || !snd_pcm_close || !snd_strerror) {
        fprintf(stderr, "missing ALSA symbol\n"); return 1;
    }
    snd_pcm_t *pcm = NULL;
    int ret = snd_pcm_open(&pcm, "hw:nassimhubufi003,4", stream, 0);
    if (ret < 0) { fprintf(stderr, "open: %s (%d)\n", snd_strerror(ret), ret); return 1; }
    /* ALSA S16_LE=2, RW_INTERLEAVED=3; 8 kHz mono, 20 ms buffer. */
    ret = snd_pcm_set_params(pcm, 2, 3, 1, 8000, 0, 20000);
    if (ret < 0) { fprintf(stderr, "set_params: %s (%d)\n", snd_strerror(ret), ret); snd_pcm_close(pcm); return 1; }
    ret = snd_pcm_prepare(pcm);
    if (ret < 0) { fprintf(stderr, "prepare: %s (%d)\n", snd_strerror(ret), ret); snd_pcm_close(pcm); return 1; }
    printf("%s CS-Voice prepared and held\n", argv[1]); fflush(stdout);
    signal(SIGTERM, stop); signal(SIGINT, stop);
    while (running) sleep(1);
    ret = snd_pcm_close(pcm);
    if (ret < 0) { fprintf(stderr, "close: %s (%d)\n", snd_strerror(ret), ret); return 1; }
    return 0;
}
