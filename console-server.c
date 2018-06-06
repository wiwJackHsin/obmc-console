/**
 * Console server process for OpenBMC
 *
 * Copyright © 2016 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <termios.h>
#include <sys/types.h>
#include <poll.h>
#include <pthread.h>
#include "console-server.h"

struct poller {
	struct handler	*handler;
	void		*data;
	poller_fn_t	fn;
	bool		remove;
};

/* we have one extra entry in the pollfds array for the VUART tty */
static const int n_internal_pollfds = 1;

/* size of the shared backlog ringbuffer */
const size_t buffer_size = 128 * 1024;

/* state shared with the signal handler */
static bool sigint;

/* populates tty_dev and tty_sysfs_devnode, using the tty kernel name */
static int tty_find_device(struct console *console)
{
	char *tty_class_device_link;
	char *tty_device_tty_dir;
	char *tty_device_reldir;
	char *tty_path_input;
	char *tty_path_input_real;
	char *tty_kname_real;
	int rc;

	tty_class_device_link = NULL;
	tty_device_tty_dir = NULL;
	tty_device_reldir = NULL;
	tty_path_input = NULL;
	tty_path_input_real = NULL;
	tty_kname_real = NULL;

	/* udev may rename the tty name with a symbol link, try to resolve */
	rc = asprintf(&tty_path_input, "/dev/%s", console->tty_kname);
	if (rc < 0)
		return -1;

	tty_path_input_real = realpath(tty_path_input, NULL);
	if (!tty_path_input_real) {
		warn("Can't find realpath for /dev/%s", console->tty_kname);
		goto out_free;
	}

	tty_kname_real = basename(tty_path_input_real);
	if (!tty_kname_real) {
		warn("Can't find real name for /dev/%s", console->tty_kname);
		goto out_free;
	}

	rc = asprintf(&tty_class_device_link,
			"/sys/class/tty/%s", tty_kname_real);
	if (rc < 0)
		goto out_free;

	tty_device_tty_dir = realpath(tty_class_device_link, NULL);
	if (!tty_device_tty_dir) {
		warn("Can't query sysfs for device %s", tty_kname_real);
		goto out_free;
	}

	rc = asprintf(&tty_device_reldir, "%s/../../", tty_device_tty_dir);
	if (rc < 0)
		goto out_free;

	console->tty_sysfs_devnode = realpath(tty_device_reldir, NULL);
	if (!console->tty_sysfs_devnode)
		warn("Can't find parent device for %s", tty_kname_real);

	rc = asprintf(&console->tty_dev, "/dev/%s", tty_kname_real);
	if (rc < 0)
		goto out_free;

	rc = 0;

out_free:
	free(tty_class_device_link);
	free(tty_device_tty_dir);
	free(tty_device_reldir);
	free(tty_path_input);
	free(tty_path_input_real);
	return rc;
}

static int tty_set_sysfs_attr(struct console *console, const char *name,
		int value)
{
	char *path;
	FILE *fp;
	int rc;

	rc = asprintf(&path, "%s/%s", console->tty_sysfs_devnode, name);
	if (rc < 0)
		return -1;

	fp = fopen(path, "w");
	if (!fp) {
		warn("Can't access attribute %s on device %s",
				name, console->tty_kname);
		rc = -1;
		goto out_free;
	}
	setvbuf(fp, NULL, _IONBF, 0);

	rc = fprintf(fp, "0x%x", value);
	if (rc < 0)
		warn("Error writing to %s attribute of device %s",
				name, console->tty_kname);
	fclose(fp);



out_free:
	free(path);
	return rc;
}

/**
 * Set console to raw mode: we don't want any processing to occur on
 * the underlying terminal input/output.
 */
static void tty_init_termios(struct console *console)
{
	struct termios termios;
	int rc;

	rc = tcgetattr(console->tty_fd, &termios);
	if (rc) {
		warn("Can't read tty termios");
		return;
	}

	//Initial default baudrate to 115200 bps
	cfsetispeed(&termios, B115200);
	cfsetospeed(&termios, B115200);

	cfmakeraw(&termios);
	rc = tcsetattr(console->tty_fd, TCSANOW, &termios);
	if (rc)
		warn("Can't set terminal raw mode for tty");
}

/**
 * Open and initialise the serial device
 */
static int tty_init_io(struct console *console)
{
	if (console->tty_sirq)
		tty_set_sysfs_attr(console, "sirq", console->tty_sirq);
	if (console->tty_lpc_addr)
		tty_set_sysfs_attr(console, "lpc_address",
				console->tty_lpc_addr);

	console->tty_fd = open(console->tty_dev, O_RDWR);
	if (console->tty_fd <= 0) {
		warn("Can't open tty %s", console->tty_dev);
		return -1;
	}

	/* Disable character delay. We may want to later enable this when
	 * we detect larger amounts of data
	 */
	fcntl(console->tty_fd, F_SETFL, FNDELAY);

	tty_init_termios(console);

	console->pollfds[console->n_pollers].fd = console->tty_fd;
	console->pollfds[console->n_pollers].events = POLLIN;

	return 0;
}

static int tty_init(struct console *console, struct config *config)
{
	const char *val;
	char *endp;
	int rc;

	val = config_get_value(config, "lpc-address");
	if (val) {
		console->tty_lpc_addr = strtoul(val, &endp, 0);
		if (endp == optarg) {
			warn("Invalid LPC address: '%s'", val);
			return -1;
		}
	}

	val = config_get_value(config, "sirq");
	if (val) {
		console->tty_sirq = strtoul(val, &endp, 0);
		if (endp == optarg)
			warn("Invalid sirq: '%s'", val);
	}

	if (!console->tty_kname) {
		warnx("Error: No TTY device specified");
		return -1;
	}

	rc = tty_find_device(console);
	if (rc)
		return rc;

	rc = tty_init_io(console);
	return rc;
}


int console_data_out(struct console *console, const uint8_t *data, size_t len)
{
	return write_buf_to_fd(console->tty_fd, data, len);
}

static void handlers_init(struct console *console, struct config *config)
{
	extern struct handler *__start_handlers, *__stop_handlers;
	struct handler *handler;
	int i, rc;
	bool is_ttyS2_and_socket_2200_in_console, is_ttyS3_and_socket_2201_in_console;


	console->n_handlers = &__stop_handlers - &__start_handlers;
	console->handlers = &__start_handlers;

	printf("%d handler%s\n", console->n_handlers,
			console->n_handlers == 1 ? "" : "s");

    //Only initial matched handlers
	for (i = 0; i < console->n_handlers; i++) {
		is_ttyS2_and_socket_2200_in_console = (strcmp(console->tty_kname, "ttyS2") == 0 && strcmp(console->handlers[i]->name, "socket_2200") == 0);
		is_ttyS3_and_socket_2201_in_console = (strcmp(console->tty_kname, "ttyS3") == 0 && strcmp(console->handlers[i]->name, "socket_2201") == 0);

		if (is_ttyS2_and_socket_2200_in_console || is_ttyS3_and_socket_2201_in_console)
		{
			handler = console->handlers[i];

			rc = 0;
			if (handler->init) {
				rc = handler->init(handler, console, config);
			}

			handler->active = rc == 0;

			printf("  %s [%sactive]\n", handler->name, handler->active ? "" : "in");
		}
	}
}

static void handlers_fini(struct console *console)
{
	struct handler *handler;
	int i;

	for (i = 0; i < console->n_handlers; i++) {
		handler = console->handlers[i];
		if (handler->fini && handler->active)
			handler->fini(handler);
	}
}

struct ringbuffer_consumer *console_ringbuffer_consumer_register(
		struct console *console,
		ringbuffer_poll_fn_t poll_fn, void *data)
{
	return ringbuffer_consumer_register(console->rb, poll_fn, data);
}

struct poller *console_poller_register(struct console *console,
		struct handler *handler, poller_fn_t poller_fn,
		int fd, int events, void *data)
{
	struct poller *poller;
	int n;

	poller = malloc(sizeof(*poller));
	poller->remove = false;
	poller->handler = handler;
	poller->fn = poller_fn;
	poller->data = data;

	/* add one to our pollers array */
	n = console->n_pollers++;
	console->pollers = realloc(console->pollers,
			sizeof(*console->pollers) * console->n_pollers);

	console->pollers[n] = poller;

	/* increase pollfds array too  */
	console->pollfds = realloc(console->pollfds,
			sizeof(*console->pollfds) *
				(n_internal_pollfds + console->n_pollers));

	/* shift the end pollfds up by one */
	memcpy(&console->pollfds[n+n_internal_pollfds],
			&console->pollfds[n],
			sizeof(*console->pollfds) * n_internal_pollfds);

	console->pollfds[n].fd = fd;
	console->pollfds[n].events = events;

	return poller;
}

void console_poller_unregister(struct console *console,
		struct poller *poller)
{
	int i;

	/* find the entry in our pollers array */
	for (i = 0; i < console->n_pollers; i++)
		if (console->pollers[i] == poller)
			break;

	assert(i < console->n_pollers);

	console->n_pollers--;

	/* remove the item from the pollers array... */
	memmove(&console->pollers[i], &console->pollers[i+1],
			sizeof(*console->pollers)
				* (console->n_pollers - i));

	console->pollers = realloc(console->pollers,
			sizeof(*console->pollers) * console->n_pollers);

	/* ... and the pollfds array */
	memmove(&console->pollfds[i], &console->pollfds[i+1],
			sizeof(*console->pollfds) *
				(n_internal_pollfds + console->n_pollers - i));

	console->pollfds = realloc(console->pollfds,
			sizeof(*console->pollfds) *
				(n_internal_pollfds + console->n_pollers));


	free(poller);
}

void console_poller_set_events(struct console *console, struct poller *poller,
		int events)
{
	int i;

	/* find the entry in our pollers array */
	for (i = 0; i < console->n_pollers; i++)
		if (console->pollers[i] == poller)
			break;

	console->pollfds[i].events = events;
}

static int call_pollers(struct console *console)
{
	struct poller *poller;
	struct pollfd *pollfd;
	enum poller_ret prc;
	int i, rc;

	rc = 0;

	/*
	 * Process poll events by iterating through the pollers and pollfds
	 * in-step, calling any pollers that we've found revents for.
	 */
	for (i = 0; i < console->n_pollers; i++) {
		poller = console->pollers[i];
		pollfd = &console->pollfds[i];

		if (!pollfd->revents)
			continue;

		prc = poller->fn(poller->handler, pollfd->revents,
				poller->data);
		if (prc == POLLER_EXIT)
			rc = -1;
		else if (prc == POLLER_REMOVE)
			poller->remove = true;
	}

	/**
	 * Process deferred removals; restarting each time we unregister, as
	 * the array will have changed
	 */
	for (;;) {
		bool removed = false;

		for (i = 0; i < console->n_pollers; i++) {
			poller = console->pollers[i];
			if (poller->remove) {
				console_poller_unregister(console, poller);
				removed = true;
				break;
			}
		}
		if (!removed)
			break;
	}

	return rc;
}

static void sighandler(int signal)
{
	if (signal == SIGINT)
		sigint = true;
}

int run_console(struct console *console)
{
	sighandler_t sighandler_save;
	int rc;

	sighandler_save = signal(SIGINT, sighandler);

	rc = 0;

	for (;;) {
		uint8_t buf[4096];

		BUILD_ASSERT(sizeof(buf) <= buffer_size);

		if (sigint) {
			fprintf(stderr, "Received interrupt, exiting\n");
			break;
		}

		rc = poll(console->pollfds,
				console->n_pollers + n_internal_pollfds, -1);
		if (rc < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				warn("poll error");
				break;
			}
		}

		/* process internal fd first */
		BUILD_ASSERT(n_internal_pollfds == 1);

		if (console->pollfds[console->n_pollers].revents) {
			rc = read(console->tty_fd, buf, sizeof(buf));
			if (rc <= 0) {
				warn("Error reading from tty device");
				rc = -1;
				break;
			}
			rc = ringbuffer_queue(console->rb, buf, rc);
			if (rc)
				break;
		}

		/* ... and then the pollers */
		rc = call_pollers(console);
		if (rc)
			break;
	}

	signal(SIGINT, sighandler_save);

	return rc ? -1 : 0;
}

static const char g_tty_console_name[MAX_TTY_NUM][8] = {"ttyS2", "ttyS3"};
static struct config *config = NULL;

void *Tty_Console_Thread(void *arg)
{
	struct console *console;
	int rc, tty_index = *(int *)arg;

	console = malloc(sizeof(struct console));
	memset(console, 0, sizeof(*console));
	console->pollfds = calloc(n_internal_pollfds, sizeof(*console->pollfds));
	console->tty_kname = g_tty_console_name[tty_index];
	console->rb = ringbuffer_init(buffer_size);

	rc = tty_init(console, config);
	if (rc)
	{
		config_fini(config);
	}
	else
	{
		handlers_init(console, config);
		rc = run_console(console);
		handlers_fini(console);
	}

	free(console->pollers);
	free(console->pollfds);
	free(console->tty_sysfs_devnode);
	free(console->tty_dev);
	free(console);

	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	int i, rc;
	const char *config_filename = NULL;
	pthread_t tty_thread[MAX_TTY_NUM];
	pthread_attr_t tty_thread_attr[MAX_TTY_NUM];

	config = config_init(config_filename);
	if (!config)
	{
		warnx("Can't read configuration, exiting.");
		return EXIT_FAILURE;
	}

	for(i = 0; i < MAX_TTY_NUM; i++)
	{
		if(pthread_attr_init(&tty_thread_attr[i]) != 0) {
			printf("\r\nttyS%d thread attribute creation failed", i+1);
		}

		if(pthread_attr_setdetachstate(&tty_thread_attr[i], PTHREAD_CREATE_DETACHED) != 0) {
			printf("\r\nttyS%d setting thread attribute creation failed", i+1);
		}

		rc = pthread_create(&tty_thread[i], &tty_thread_attr[i], Tty_Console_Thread, (void *)&i);
		if(rc != 0)
		{
			printf("\r\nttyS%d Thread creation failed: svr_node_thread", i+1);
			exit(-1);
		}

		sleep(3);
	}

	while(1) {
		sleep(3);
	}

	return 0;
}
