/*
 * ingest_common.c — shared memory management for ingest types.
 */

#include "ingest.h"
#include <stdlib.h>

void message_free(message_t *msg)
{
    if (!msg) return;
    free(msg->payload);
    free(msg);
}

void session_free(session_t *session)
{
    if (!session) return;
    for (size_t i = 0; i < session->count; i++)
        free(session->messages[i].payload);
    free(session->messages);
}

void trace_free(trace_t *trace)
{
    if (!trace) return;
    for (size_t i = 0; i < trace->count; i++)
        session_free(&trace->sessions[i]);
    free(trace->sessions);
    free(trace);
}
