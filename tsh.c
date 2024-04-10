/**************************************************************************************************
 * @file tsh.c
 * @brief A tiny shell program with job control and I/0 redirection.
 *
 *  My implementation of a simple Linux shell, an interactive
 *  command-line interpreter that runs programs on behalf of the user. The shell
 *  prints a prompt, waits for a command and then carries out some action based
 *  on some command. Commands fall into two broad categories:
 *
 *  not Built-in commands: These are paths to executable files that
 *  the shell runs in a child process within the shell so as to not corrupt the
 *  state of its own process. Child processes created as a result of
 *  interpreting such a command are referred to as jobs. The shell waits for
 *  forground jobs to terminate before resuming execution while the shell does
 *  not wait for the background job to terminate before resuming execution. If a
 *  command ends with an '&' then the shell runs the job in the background.
 *  Otherwise it is run in the foreground.
 *
 *  Built-in commands: These commands run within the shell's process.
 *  The build-in commands supported by this shell are:
 *
 *              quit - Terminates the shell
 *              jobs - Lists all background jobs
 *              bg (%)job - Resumes a job by sending it a SIGCONT signal then
 *                          runs it in background.
 *              fg (%)job - Resumes a job by sending it a SIGCONT signal then
 *                          runs it in foreground.
 *
 *  For the bg/fg commands the job argument can either be a process ID
 *  or job ID. Prepending the argument with '%' ensures that the argument is
 *  interpreted to be a job ID. The shell manages 3 signals, namely:
 *  SIGINT- Recieved by CTRL-C
 *  SIGSTP - Recieved bt CTRL-Z
 *  SIGCHLD - Recieved when a child process stops/terminates.
 *
 *  The shell also supports I/O redirection. The output of a non
 *  build-in command can be redirected from stdout to another location (eg. a
 *  file) using '>'. Similarly, the input source can be redirected from STDIN
 *  from another location using '<'. For builtin commands, This shell only
 *  supports output redirection for the build-in command 'jobs'.
 *
 *
 * @author Purusottam Samal <psamal@andrew.cmu.edu>
 **************************************************************************************************/

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Environment Variables */
extern char **environ;

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

int parse_jid(struct cmdline_tokens *token, pid_t *pid, jid_t *jid);
void process_state(struct cmdline_tokens *token, job_state state);
void process_jobs(struct cmdline_tokens *token);
void process_redirection(struct cmdline_tokens *token);
void process_builtin_none(const char *cmdline, struct cmdline_tokens *token,
                          job_state state);

/**
 * @brief Initializes the data structures (job_list) and variables
 * required for the shell operation. Executes the shells read/eval loop/
 *
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief Handles the parsing and processing of command line arguments.
 *
 * @param[in] cmdline  The command line to parse.
 */
void eval(const char *cmdline) {

    /*
    Parse the command line
    Arguments, input/output redirection
    files, and whether the command line corresponds to a background job are
    stored in token
    */
    parseline_return parse_result;
    struct cmdline_tokens token;
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    /*
    Commands fall into 4 broad categories and are processed in diffrent ways
    See helper function documentation corresponding to each function call in
    the switch statement for fore information
    */

    switch (token.builtin) {

    case BUILTIN_QUIT:
        exit(0);
        break;

    case BUILTIN_FG:
        process_state(&token, FG);
        break;

    case BUILTIN_BG:
        process_state(&token, BG);
        break;

    case BUILTIN_JOBS:
        process_jobs(&token);
        break;

    case BUILTIN_NONE:;
        job_state state = (parse_result == PARSELINE_FG) ? FG : BG;
        process_builtin_none(cmdline, &token, state);
        break;

    default:
        break;
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief Handles the SIGCHLD signal which is sent to the parent when each
 * process either terminates or stops. Because signals can be coalesced, the
 * handler attempts to reap all child processes which have terminated. SIGCHLD,
 * SIGINT, SIGSTP are blocked to protect against race conditions.
 *
 * @param[in] sig  The signal being handled
 *
 */
void sigchld_handler(int sig) {

    /* errno is saved. To be restored on exit. */
    int old_errno = errno;
    int status;

    /* SIGCHLD, SIGINT, SIGSTP are blocked */
    sigset_t mask, prev_mask;
    pid_t pid;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    /* Attempt to reap all terminated children */
    while ((pid = waitpid(-1, &status, WUNTRACED | WNOHANG)) > 0) {

        jid_t jid = job_from_pid(pid);

        if (job_exists(jid)) {
            /* Terminated normally or by signal */
            if (WIFEXITED(status) || WIFSIGNALED(status)) {

                delete_job(jid);

                if (WIFSIGNALED(status))
                    sio_printf("Job [%d] (%d) terminated by signal %d\n", jid,
                               pid, WTERMSIG(status));

            } else if (WIFSTOPPED(status)) { /* Stopped by a signal */

                /* Change state in job_list */
                job_set_state(jid, ST);
                sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                           WSTOPSIG(status));
            }
        }
    }

    if (pid == -1 && errno != ECHILD)
        sio_printf("waitpid error");

    // Unblock
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = old_errno;
    return;
}

/**
 * @brief Handles the SIGINT signal which is sent to the parent when CTRL-C is
 * recieved from keyboard. The handler forwards the signal to the entire process
 * group containing, the foreground job. SIGCHLD, SIGINT, SIGSTP are blocked to
 * protect against race conditions.
 *
 * @param[in] sig  The signal being handled
 *
 */
void sigint_handler(int sig) {

    /* Save errno. To be restored on exit. */
    int old_errno = errno;

    /* SIGCHLD, SIGINT, SIGSTP are blocked */
    sigset_t mask, prev_mask;
    pid_t pid;
    jid_t jid;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    jid = fg_job(); // Get foreground job

    if (job_exists(jid)) {
        /* Send signal to the process group containing foreground job */
        pid = job_get_pid(jid);
        pid_t npid = 0 - pid;

        /* Negating pid sends sig to every process in process group |pid| */
        if (kill(npid, sig) == -1)
            perror("kill error.");
    }

    // Unblock
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = old_errno;
    return;
}

/**
 * @brief Handles the SIGSTP signal which is sent to the parent CTRL-Z is
 * recieved from keyboard. The handler forwards the signal to the entire process
 * group containing, the foreground job. SIGCHLD, SIGINT, SIGSTP are blocked to
 * protect against race conditions.
 *
 * @param[in] sig  The signal being handled
 *
 */
void sigtstp_handler(int sig) {

    /* Save errno. To be restored on exit. */
    int old_errno = errno;

    /* SIGCHLD, SIGINT, SIGSTP are blocked */
    sigset_t mask, prev_mask;
    pid_t pid;
    jid_t jid;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    jid = fg_job(); // Get foreground job

    if (job_exists(jid)) {
        /* Send signal to the process group containing foreground job */
        pid = job_get_pid(jid);

        pid_t npid = 0 - pid;

        /* Negating pid sends sig to every process in process group |pid| */
        if (kill(npid, sig) == -1)
            perror("kill error.");
    }

    // Unblock
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    errno = old_errno;

    return;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}

/* Additional Helpers */

/**
 * @brief Parses and extracts job ID from arguments either directly if '%' is
 * prepending the argument or indirectly from the process ID. Called as a helper
 * in process_state
 *
 * @pre token->argc >= 2. There must be enough arguments to parse.
 *
 * @param[in] token  Pointer to a cmdline_tokens structure, which will
 *                      be populated with the parsed tokens.
 * @param[in] pid  A pointer whose value is set to the parsed process ID
 * @param[in] jid  A pointer whose value is set to the parsed job ID
 *
 * @return 0 if parse was succesful else -1
 */
int parse_jid(struct cmdline_tokens *token, pid_t *pid, jid_t *jid) {

    /* Argument is JID */
    if (token->argv[1][0] == '%') {

        /* Check if digit */
        if (!isdigit(token->argv[1][1])) {
            sio_eprintf("%s: argument must be a PID or %%jobid\n",
                        token->argv[0]);
            return -1;
        }

        *jid = atoi(&token->argv[1][1]);

        if (job_exists(*jid)) {
            *pid = job_get_pid(*jid);
        } else {
            sio_printf("%s: No such job\n", token->argv[1]);
            return -1;
        }
    } else { /* Argument is PID */

        /* Check if digit */
        if (!isdigit(token->argv[1][0])) {
            sio_eprintf("%s: argument must be a PID or %%jobid\n",
                        token->argv[0]);
            return -1;
        }

        *pid = atoi(&token->argv[1][0]);
        *jid = job_from_pid(*pid);
    }

    return 0;
}

/**
 * @brief Handles the execution when recieving a bg/fg buitin command.
 * This function resumes a job by sending a SIGCONT signal and then
 * runs it in the forground or background depending on the state passed.
 * The state of the corresponding jobs are also appropriately changed in
 * the joblist. Signal safety is ensured by temporarily blocking all signals
 * before accessing the joblist. Called in eval.
 *
 * @param[in] token  Pointer to a cmdline_tokens structure, which will
 *                      be populated with the parsed tokens.
 * @param[in] state  The state to set the job to.
 *
 */
void process_state(struct cmdline_tokens *token, job_state state) {

    sigset_t full_mask, prev_mask;
    pid_t pid;
    jid_t jid;
    sigfillset(&full_mask);

    /* Check arg buffer meets minimum size */
    if (token->argc < 2) {
        sio_eprintf("%s command requires PID or %%jobid argument\n",
                    token->argv[0]);
        return;
    }

    /* Block all signals */
    sigprocmask(SIG_BLOCK, &full_mask, &prev_mask);

    /* Parse JID */
    if (parse_jid(token, &pid, &jid) != 0) {
        // If fail, unblock and return
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return;
    }

    if (job_exists(jid)) {
        /* If stopped, send SIGCONT */
        if (job_get_state(jid) == ST) {
            pid = job_get_pid(jid);

            pid_t npid = 0 - pid;

            /* Negating pid sends sig to every process in process group |pid| */
            if (kill(npid, SIGCONT) == -1)
                perror("kill error.");
        }
        job_set_state(jid, state);

    } else {
        sio_printf("%s No such job\n", token->argv[1]);
        // Unblock
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        return;
    }

    /* If job is now foreground, parent must wait for it to terminate */
    if (fg_job() != 0) {

        while (fg_job() == jid) {
            sigsuspend(&prev_mask);
        }

    } else {
        sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
    }

    /* Unblock */
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    return;
}

/**
 * @brief Handles the execution when recieving a jobs buitin command.
 * This function handles lising all the background jobs when a job command
 * is recieved. Additionally, the fuction supports output redirection for
 * the job command. Called in eval.
 *
 * @param[in] token  Pointer to a cmdline_tokens structure, which will
 *
 */
void process_jobs(struct cmdline_tokens *token) {
    sigset_t mask, prev_mask;
    int outfile_fd;

    /* Initialize masks */
    sigemptyset(&prev_mask);
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    // Block to prevent job list modification
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    if (token->outfile != NULL) {

        /* Redirect output of jobs to outfile if not null */
        /* Open or create outfile */
        /* Overwrite to outfile */

        outfile_fd =
            open(token->outfile, O_WRONLY | O_CREAT | O_TRUNC, DEF_MODE);

        /* Error handling */
        if (outfile_fd < 0) {
            if (errno == EACCES) {
                sio_eprintf("%s: Permission denied\n", token->outfile);
            }
            // Unblock
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            return;
        }

        list_jobs(outfile_fd);

        if (close(outfile_fd) < 0) {
            sio_eprintf("outfile close error\n");
            // Unblock
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            exit(-1);
        }
    } else { // Output to stdout
        list_jobs(STDOUT_FILENO);
    }

    // Unblock
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    return;
}

/**
 * @brief Handles I/O redirection if warranted. infile is redirected to
 * STDIN and outfile is redirected to STDOUT. Called in the process_builtin_none
 * after forking a child process their file descriptors can be changed.
 *
 * @param[in] token  Pointer to a cmdline_tokens structure, which will
 *                      be populated with the parsed tokens.
 *
 */
void process_redirection(struct cmdline_tokens *token) {

    int infile_fd, outfile_fd;

    /* Redirect infile to STDIN */
    if (token->infile != NULL) {

        /* Read Only */
        infile_fd = open(token->infile, O_RDONLY);

        /* Error handling (open) */
        if (infile_fd < 0) {

            if (errno == EACCES) { /* Bad Permission */
                sio_eprintf("%s: Permission denied\n", token->infile);
            } else if (errno == ENOENT) { /* File does not exist */
                sio_eprintf("%s: No such file or directory\n", token->infile);
            }
            exit(-1);
        }

        /* Redirect */
        if (dup2(infile_fd, STDIN_FILENO) < 0) {
            sio_eprintf("infile dup2 error\n");
            exit(-1);
        }

        if (close(infile_fd) < 0) {
            sio_eprintf("infile close error\n");
            exit(-1);
        }
    }

    /* Redirect outfile to STDOUT */
    if (token->outfile != NULL) {

        /* Open or create outfile */
        /* Overwrite to outfile */
        outfile_fd =
            open(token->outfile, O_WRONLY | O_CREAT | O_TRUNC, DEF_MODE);

        /* Error handling (open) */
        if (outfile_fd < 0) {
            if (errno == EACCES) {
                sio_eprintf("%s: Permission denied\n", token->outfile);
            }
            exit(-1);
        }

        /* Redirect */
        if (dup2(outfile_fd, STDOUT_FILENO) < 0) {
            sio_eprintf("outfile dup2 error\n");
            exit(-1);
        }

        if (close(outfile_fd) < 0) {
            sio_eprintf("outfile close error\n");
            exit(-1);
        }
    }
}

/**
 * @brief Handles the execution when recieving a non built-in command.
 * Executes executable files as child processes within the shell. Child
 * processes Waits for forground jobs to terminate before resuming execution,
 * does not wait for the background jobs. Called in eval.
 *
 * @param[in] cmdline: The command line used to start the job.
 *
 * @param[in] token  Pointer to a cmdline_tokens structure, which will
 *                      be populated with the parsed tokens.
 * @param[in] state  The state to set the job to.
 *
 */
void process_builtin_none(const char *cmdline, struct cmdline_tokens *token,
                          job_state state) {
    pid_t pid;
    jid_t jid;
    sigset_t full_mask, mask, prev_mask;

    /* Initialize masks */
    sigfillset(&full_mask);
    sigemptyset(&prev_mask);
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    /* Block SIGCHLD to avoid race between add_job and delete_job */
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);

    /* Create Child Process */
    /* In a separate process group */
    if ((pid = fork()) < 0) {
        perror("fork error");
        exit(1);
    }

    setpgid(0, 0);

    if (pid == 0) /* Child Process runs user job */
    {
        /* Redirect IO */
        process_redirection(token);
        /* Child inherits parents signal mask */
        /* Must unblock */
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        execve(token->argv[0], token->argv, environ);
        // execve fails
        if (errno == ENOENT) {
            sio_eprintf("%s: No such file or directory\n", token->argv[0]);
        } else if (errno == EACCES) {
            sio_eprintf("%s: Permission denied\n", token->argv[0]);
        }
        exit(-1);
    }

    /* Parent Process */
    /* Block before adding to job list */
    sigprocmask(SIG_BLOCK, &full_mask, NULL);
    jid = add_job(pid, state, cmdline);

    /* If Foreground, parent must wait for it to terminate */
    if (fg_job() != 0) {

        while (fg_job() == jid) {
            sigsuspend(&prev_mask);
        }

    } else {
        sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
    }

    /* Unblock */
    sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    return;
}