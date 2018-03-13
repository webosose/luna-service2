#include <luna-service2/lunaservice.h>
#include <luna-service2/lunaservice-meta.h>
#include <pbnjson.h>
#include <time.h>
#include <glib-unix.h>

const static char * const SUBSCRIPTION_KEY = "getSystemTime";
const static int TIMEOUT = 1500;

typedef struct TimeService {
	LSHandle *sh;
	int totalCallCount;
	GMainLoop *mainLoop;
} TimeService;

/**
 * @brief handleIdleTimeoutCallback  which will be called if there are no activity
 * on LS2 bus, regarding our service, for timeout milliseconds.
 * @param userData pointer to timeService struct
 */
static void handleIdleTimeoutCallback(void *userData) {
	TimeService *timeService = (TimeService *) userData;
	g_main_loop_quit(timeService->mainLoop);
}

/**
 * @brief printError helper to output pbnjson error
 * @param message
 * @param JSONerror
 */
static inline void printError(const char *message, jerror *JSONerror) {
	char errorBuffer[255];
	jerror_to_string(JSONerror, errorBuffer, sizeof(errorBuffer));
	fprintf(stderr, "%s : %s\n", message, errorBuffer);
}

/**
 * @brief configReadCallback callback function that process
 * com.webos.service.config/getConfigs answer
 * @param sh
 * @param message
 * @param ctx pointer to timeService struct
 * @return true
 */
bool configReadCallback(LSHandle *sh, LSMessage *message, void *ctx) {
	int timeout = 0;
	jerror *JSONerror = NULL;
	TimeService *timeService = (TimeService *) ctx;

	const char *inputSchema = "{ \"type\" : \"object\","
	    "\"required\": [\"configs\"],"
	    "\"properties\" : {"
	        "\"configs\" : {"
	            "\"type\" : \"object\","
	            "\"required\": [\"" SERVICE_NAME ".timeout\"],"
	            "\"properties\" : {"
	                "\"" SERVICE_NAME ".timeout\" : "
	                    "{\"type\" : \"number\" }"
	            "}"
	        "}"
	    "}"
	"}";
	jschema_ref schema = jschema_create(j_cstr_to_buffer(inputSchema), &JSONerror);

#ifndef NDEBUG
	if (JSONerror) {
		printError("Failed to create schema", JSONerror);
		abort();
	}
#endif

	jvalue_ref jvalueFromMessage = jdom_create(j_cstr_to_buffer(LSMessageGetPayload(message)), schema, &JSONerror);
	jschema_release(&schema);
	if (JSONerror) {
		printError("Failed to parse reply", JSONerror);
		jerror_free(JSONerror);
		return true;
	}

	jvalue_ref number = jobject_get(
	    jobject_get(jvalueFromMessage, J_CSTR_TO_BUF("configs")),
	    J_CSTR_TO_BUF(SERVICE_NAME ".timeout")
	);
	if (jnumber_get_i32(number, &timeout) == CONV_OK) {
		LSIdleTimeout(timeout, handleIdleTimeoutCallback, timeService, g_main_loop_get_context(timeService->mainLoop));
	}
	return true;
}

/**
 * @brief getConfigTimeout short wrapper to make call to com.webos.serviceconfig/getConfig.
 * Answer processed asynchronously.
 * @param timeService pointer to timeService struct
 */
static void getConfigTimeout(TimeService *timeService) {
	LSError lserror;
	LSErrorInit(&lserror);

	if (!LSCall(timeService->sh, "luna://com.webos.service.config/getConfigs",
	            "{\"configNames\":[\"" SERVICE_NAME ".timeout\"]}",
	            configReadCallback, timeService, NULL, &lserror)) {
		fprintf(stderr, "Failed call to com.webos.service.config, %s", lserror.message);
	}

	LSErrorFree(&lserror);
}

/**
 * @brief timeoutCallback callback, which call every TIMEOUT milliseconds.
 * Callback sends to all subscribed clients current date and time.
 *
 * @param data handle
 * @return true
 */
gboolean timeoutCallback(void *data) {
	TimeService *timeService = (TimeService *) data;
	assert(timeService->sh);
	if (LSSubscriptionGetHandleSubscribersCount(timeService->sh, SUBSCRIPTION_KEY) == 0) {
		return true;
	}
	LSError lsError;
	LSErrorInit(&lsError);

	time_t ltime;
	time(&ltime);
	struct tm local_tm;
	localtime_r(&ltime, &local_tm);
	char buffer[80];
	strftime(buffer, sizeof(buffer), "%c", &local_tm);

	jvalue_ref responseJSON;
	responseJSON = jobject_create_var(
		jkeyval(J_CSTR_TO_JVAL("subscribed"), jboolean_create(true)),
		jkeyval(J_CSTR_TO_JVAL("time"), j_cstr_to_jval(buffer)),
		NULL
	);

	LSSubscriptionReply(timeService->sh, SUBSCRIPTION_KEY, jvalue_tostring_simple(responseJSON), &lsError);
	j_release(&responseJSON);

	return true;
}

/**
 * @brief getTimeMethod example of callback that process API call over LS2.
 * @param handle LS2 handle on which service is registered and incoming call is received
 * @param message
 * @param userdata pointer timeService struct
 * @return true on success
 */
bool getTimeMethod(LSHandle *handle, LSMessage *message, void *userdata) {
	TimeService *timeService = (TimeService *) userdata;
	timeService->totalCallCount++;

	jvalue_ref responseJSON = NULL;
	bool result = true;
	char *errorText;
	char replyArray[255];

	jerror *JSONerror = NULL;
	bool subscribe;

	time_t ltime;
	time(&ltime);
	struct tm local_tm;
	localtime_r(&ltime, &local_tm);
	char buffer[80];
	strftime(buffer, sizeof(buffer), "%c", &local_tm);

	/* get value of subscribed flag in JSON message */
	jvalue_ref message_ref = jdom_create(j_cstr_to_buffer(LSMessageGetPayload(message)), jschema_all(), &JSONerror);

	if (jis_valid(message_ref)) {
		(void) jboolean_get(jobject_get(message_ref, J_CSTR_TO_BUF("subscribe")), &subscribe);
	} else {
		result = false;
		jerror_to_string (JSONerror, replyArray, sizeof (replyArray));
		errorText = replyArray;
	}

	LSError lsError;
	LSErrorInit(&lsError);

	if (result) {
		if (subscribe) {
			if (LSSubscriptionAdd(handle, SUBSCRIPTION_KEY, message, NULL)) {
				result = true;
			} else {
				errorText = "Failed add to subscription list";
				result = false;
			}
		}
	}

	if (result) {
		responseJSON = jobject_create_var(
			jkeyval(J_CSTR_TO_JVAL("returnValue"), jboolean_create(result)),
			jkeyval(J_CSTR_TO_JVAL("time"), j_cstr_to_jval(buffer)),
			jkeyval(J_CSTR_TO_JVAL("subscribed"), jboolean_create(subscribe)),
			NULL
		);
	} else {
		responseJSON = jobject_create_var(
			jkeyval(J_CSTR_TO_JVAL("returnValue"), jboolean_create(result)),
			jkeyval(J_CSTR_TO_JVAL("errorText"), J_CSTR_TO_JVAL(errorText)),
			jkeyval(J_CSTR_TO_JVAL("errorCode"), jnumber_create_i32(1)),
			NULL
		);
	}

	if (!LSMessageReply(handle, message, jvalue_tostring_simple(responseJSON), &lsError)) {
		fprintf(stderr, "failed reply to client: %s\n", lsError.message);
		result = false;
	}

	LSErrorFree(&lsError);
	j_release(&responseJSON);
	return result;
}

/**
 * @brief serviceMethods array with methods to register.
*/
LSMethod serviceMethods[] = {
	{ "timerMethod", getTimeMethod, LUNA_METHOD_FLAG_VALIDATE_IN },
	{}
};

/**
 * @brief init initialization function
 * @param timeService
 * @return true on success, false on failure.
 */
static bool init(TimeService *timeService) {
	LSError error;
	bool retVal = false;
	LSErrorInit(&error);
	jerror *jerrorPtr = NULL;

	do {
		if (!LSRegister(SERVICE_NAME, &timeService->sh, &error)) {
			break;
		}

		getConfigTimeout(timeService);
		const char * const category = "/";

		if (!LSRegisterCategory(timeService->sh, category, serviceMethods, NULL, NULL, &error)) {
			break;
		}
		if (!LSCategorySetData(timeService->sh, category, timeService, &error)) {
			break;
		}

		if (!LSGmainAttach(timeService->sh, timeService->mainLoop, &error)) {
			break;
		}

		/* schema inside method description used to validate input message
		 * before user callback invocation */
		const char *description =
			"{"
				"\"methods\": {"
					"\"timerMethod\": {"
						"\"call\": {"
							"\"type\": \"object\","
							"\"description\": \"Returns current time in reply. If subscribe flag set to true, reply on regular interval\","
							"\"additionalProperties\": true"
						"}"
					"}"
			"}}";

		jvalue_ref categoryDescription = jdom_create(j_cstr_to_buffer(description), jschema_all(), &jerrorPtr);
#ifndef NDEBUG
		if (!jis_valid(categoryDescription)) {
			printError("Failed parse description", jerrorPtr);
			abort();
		}
#endif
		if (!LSCategorySetDescription(timeService->sh, category, categoryDescription, &error)) {
			fprintf(stderr, "Failed to set category data %s", error.message);
			j_release(&categoryDescription);
			break;
		}
		retVal = true;
	} while (false);

	if (LSErrorIsSet(&error)) {
		LSErrorPrint(&error, stderr);
	}
	jerror_free(jerrorPtr);
	LSErrorFree(&error);
	return retVal;
}

/**
 * @brief quit signal handler
 * @param data pointer to timeService struct
 * @return true
 */
static gboolean quit(void *data) {
	TimeService *timeService = (TimeService *) data;
	g_main_loop_quit(timeService->mainLoop);
	return true;
}

int main() {
	int result = 1;

	TimeService timeService;
	timeService.totalCallCount = 0;
	timeService.mainLoop = g_main_loop_new(NULL, FALSE);

	/* add signal handler to custom GMainContext */
	GSource *source = g_unix_signal_source_new(SIGINT);
	g_source_set_callback(source, quit, &timeService, NULL);
	g_source_attach(source, g_main_loop_get_context(timeService.mainLoop));
	g_source_unref(source);

	/* add signal handler to default GMainContext using short syntax */
	g_unix_signal_add(SIGTERM, quit, &timeService);

	g_timeout_add_full(G_PRIORITY_DEFAULT, TIMEOUT, timeoutCallback, &timeService, NULL);

	if (init(&timeService)) {
		g_main_loop_run(timeService.mainLoop);
		result = 0;
	}

	g_main_loop_unref(timeService.mainLoop);
	return result;
}
