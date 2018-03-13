#include <memory>
#include <luna-service2/lunaservice.hpp>
#include <pbnjson.hpp>
#include <ctime>

using std::string;

class TimeService : public LS::Handle {
private:
	const static int TIMEOUT = 1000;
	using MainLoopT = std::unique_ptr<GMainLoop, void(*)(GMainLoop*)>;

	LS::SubscriptionPoint subscriptionPoint;
	MainLoopT mainLoopPtr = { g_main_loop_new(nullptr, false), g_main_loop_unref };
	int totalCallCount;

public:
	TimeService() :
	    LS::Handle(LS::registerService(SERVICE_NAME)),
	    totalCallCount(0) {
	}

	TimeService(TimeService const&) = delete;
	TimeService(TimeService &&) = delete;
	TimeService& operator =(TimeService const&) = delete;
	TimeService& operator =(TimeService && ) = delete;

	/**
	 * @brief timeoutCallback callback, which called every TIMEOUT milliseconds.
	 * Callback sends to all subscribed clients current date and time.
	 * Function return false after MAX_SEND_COUNT repeated and timer stop.
	 *
	 * @param data pointer to this object
	 * @return true
	*/
	static gboolean timeoutCallback(void *data) {
		TimeService *timeService = static_cast<TimeService *>(data);

		if (timeService->subscriptionPoint.getSubscribersCount() == 0) {
			return true;
		}
		time_t ltime;
		time(&ltime);
		struct tm local_tm;
		localtime_r(&ltime, &local_tm);
		char buffer[80];
		strftime(buffer, sizeof(buffer), "%c", &local_tm);

		pbnjson::JValue responseJSON = pbnjson::JObject {
			{ "subscribed", true },
			{ "time", buffer }
		};

		timeService->subscriptionPoint.post(responseJSON.stringify().c_str());

		return true;
	}

	/**
	 * @brief timerMethod example of callback function
	 * @param lsMessage
	 * @return
	 */
	bool timerMethod(LSMessage &lsMessage) {
		LS::Message request(&lsMessage);
		totalCallCount++;

		bool subscription = false;
		pbnjson::JValue responseJSON;

		time_t ltime;
		time(&ltime);
		struct tm local_tm;
		localtime_r(&ltime, &local_tm);
		char buffer[80];
		strftime(buffer, sizeof(buffer), "%c", &local_tm);

		pbnjson::JValue parsed = pbnjson::JDomParser::fromString(request.getPayload(), pbnjson::JSchema::AllSchema());
		if (parsed.isError()) {
			responseJSON = pbnjson::JObject{{"returnValue", false}, {"errorText", "Failed to parse params"}, {"errorCode", 1}};
		} else {
			subscription = parsed["subscribe"].asBool();
			responseJSON = pbnjson::JObject{{"returnValue", true}, {"time", buffer}, {"subscribed", subscription}};
		}

		if (subscription) {
			subscriptionPoint.setServiceHandle(this);
			subscriptionPoint.subscribe(request);
		}

		try {
			request.respond(responseJSON.stringify().c_str());
		} catch(LS::Error &err) {
			std::cerr << err << std::endl;
		}
		return true;
	}

	/**
	 * @brief run register methods, attach to loop and run mainloop
	 */
	void run() {
		LS_CATEGORY_BEGIN(TimeService, "/")
		        LS_CATEGORY_METHOD(timerMethod, LUNA_METHOD_FLAG_VALIDATE_IN)
		LS_CATEGORY_END;

		//struct to input message
		const char * const methodSchemaStr = R"(
		  {
		    "methods": {
		      "timerMethod": {
		        "call": {
		          "type": "object",
		          "description": "Returns current time in reply. If subscribe flag set to true, reply on regular interval",
		          "additionalProperties": true
		        }
		      }
		    }
		  })";

		jerror *JSONerror = nullptr;
		jvalue_ref methodSchema = jdom_create(j_cstr_to_buffer(methodSchemaStr), jschema_all(), &JSONerror);
#ifndef NDEBUG
		if (JSONerror) {
			char replyArray[255];
			jerror_to_string (JSONerror, replyArray, sizeof(replyArray));
			std::cerr << "Failed to parse schema: " << replyArray << std::endl;
			abort();
		}
#endif
		setCategoryDescription("/", methodSchema);

		jerror_free(JSONerror);
		j_release(&methodSchema);

		g_timeout_add_full(G_PRIORITY_DEFAULT, TIMEOUT, timeoutCallback, this, NULL);

		//attach to mainloop and run it
		attachToLoop(mainLoopPtr.get());
		g_main_loop_run(mainLoopPtr.get());
	}

	/**
	 * @brief handleIdleTimeoutCallback which will be called if there are no activity
	 * on LS2 bus, regarding our service, for timeout milliseconds.
	 * @param userData pointer to timeService class
	 */
	static void handleIdleTimeoutCallback(void *userData) {
		TimeService *timeService = static_cast<TimeService *>(userData);
		g_main_loop_quit(timeService->mainLoopPtr.get());
	}

	/**
	 * @brief configReadCallback callback function that process
	 * com.webos.service.config/getConfigs answer
	 * @param sh
	 * @param message
	 * @param ctx pointer to timeService class
	 * @return true
	 */
	static bool configReadCallback(LSHandle *sh, LSMessage *message , void *ctx) {
		TimeService *timeService = static_cast<TimeService*>(ctx);
		pbnjson::JSchema schema = pbnjson::JSchema::fromString(R"(
		  {
		    "type" : "object",
		    "required": ["configs"],
		      "properties" : {
		        "configs" : {
		          "type" : "object",
		          "required": [")" SERVICE_NAME R"(.timeout"],
		          "properties" : {
		             ")" SERVICE_NAME R"(.timeout" : { "type" : "number" }
		          }
		        }
		      }
		  })");

#ifndef NDEBUG
		if (schema.isError()) {
			std::cerr << schema.errorString() << std::endl;
			abort();
		}
#endif

		// get JSON object from message
		pbnjson::JValue parsed = pbnjson::JDomParser::fromString(LSMessageGetPayload(message), schema);
		if (parsed.isError()) {
			std::cerr << parsed.errorString() << std::endl;
			return true;
		}

		//get integer value from object
		int timeout = parsed["configs"][SERVICE_NAME".timeout"].asNumber<int>();
		if (timeout != 0) {
			LSIdleTimeout(timeout, handleIdleTimeoutCallback, timeService,
			              g_main_loop_get_context(timeService->mainLoopPtr.get()));
		}
		return true;
	}
};

int main(int argc, char ** argv) {
	try {
		TimeService timeService;

		/* Make call to "com.webos.service.config" to get exit timeout value.
		* Call obect must be hold until answer is processed.
		* This will happen once "timeService" starts its mainloop.
		*/
		LS::Call call = timeService.callOneReply("luna://com.webos.service.config/getConfigs",
		                     "{\"configNames\":[\"" SERVICE_NAME ".timeout\"]}",
		                     TimeService::configReadCallback, &timeService, nullptr);
		timeService.run();
	} catch(LS::Error &err) {
		std::cerr << err << std::endl;
		return 1;
	}
	return 0;
}
