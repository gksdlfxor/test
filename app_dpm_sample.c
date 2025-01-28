/*
 * FreeRTOS V202112.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

/* 
 * This file was derived and modified from "FleetProvisioningDemoExample.c",
 * "ShadowDemoMainExample.c" and "JobsDemoExample.c"
 */

/* Standard includes. */
#include <string.h>
#include <stdio.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"

#include "app_provision.h"
#include "app_aws_user_conf.h"
//#include "command_net.h" //[tin aws work]
//#include "da16x_network_main.h" //[tin aws work]
#include "app_thing_manager.h"
#include "app_dpm_thread.h"
#include "app_dpm_interface.h"
#include "app_topic_name_manager.h"
#include "aws_iot_error.h"
#include "ota_update.h"
//#include "json.h"  //[tin aws work]


#if defined(__SUPPORT_UPSS__)
#include "upss.h"
#endif // __SUPPORT_UPSS__

#include "logging_levels.h"

#if defined(LIBRARY_LOG_LEVEL)
#undef LIBRARY_LOG_LEVEL
#endif
#if defined(LIBRARY_LOG_NAME)
#undef LIBRARY_LOG_NAME
#endif
#define LIBRARY_LOG_LEVEL	 LOG_INFO
#define LIBRARY_LOG_NAME	"DoorLockDemo"

#include "logging_stack.h"

/* Jobs library header. */
#include "jobs.h"

/* Shadow API header. */
#include "shadow.h"

/* JSON library includes. */
#include "core_json.h"

/* mbedTLS include for configuring threading functions */
#include "mbedtls/threading.h"
#include "threading_alt.h"

/* TinyCBOR library for CBOR encoding and decoding operations. */
#include "cbor.h"

/* corePKCS11 includes. */
#include "core_pkcs11.h"
#include "core_pkcs11_config.h"

/* AWS IoT Fleet Provisioning Library. */
#include "fleet_provisioning.h"

/* Demo includes. */
#include "mqtt_pkcs11_demo_helpers.h"
#include "pkcs11_operations.h"
#include "tinycbor_serializer.h"
//#include "using_mbedtls_pkcs11.h"
#include "transport_mbedtls_pkcs11.h"//[tin aws work]
#include "app_atcommand_pal.h"
#undef printf
//#define printf	PRINTF //[tin aws work]

#if defined(__SUPPORT_USR_NVRAM__)//[tin aws work]
#include "api_usr_nvram.h"
#endif

#include "rm_lwip_helper.h"//[tin aws work]
#include "iface_defs.h"//[tin aws work]

#define SNTP_TRY_COUNT						15
#define MAX_URL_LEN							256
#define MAX_RETRY_CNT_TO_SLEEP              3

/**
 * @brief Predefined shadow name.
 *
 * Defaults to unnamed "Classic" shadow. Change to a custom string to use a named shadow.
 */
#define DEFAULT_SHADOW_NAME     SHADOW_NAME_CLASSIC

/**
 * @brief Size of AWS IoT Thing name buffer.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_CreateThing.html#iot-CreateThing-request-thingName
 */
#define MAX_THING_NAME_LENGTH       128

/**
 * @brief Size of AWS subscription topic buffer
 */
#define MAX_SUBSCRIBE_TOPIC_LEN		256

/**
 * @brief Size of AWS publish payload buffer
 */
#define MAX_PUBLISH_PAYLOAD_LEN		512

/**
 * @brief RECV Timeout when UC wakeup on DPM mode
 */
#define UC_WAKEUP_RECV_TIMEOUT		200

/**
 * @brief RECV Timeout when DM_FINISH_DEVICE on DPM mode
 */
#define FINISH_LOOP_RECV_TIMEOUT	50

/**
 * @brief Maximum count of waiting PUB ACK or Job next flag before going to DPM sleep
 */
#define MAX_PUB_ACK_OR_JOB_WAIT_CNT	5

/**
 * @brief The length of #DEFAULT_SHADOW_NAME.
 */
#define SHADOW_NAME_LENGTH    ( ( uint16_t ) ( sizeof( DEFAULT_SHADOW_NAME ) - 1 ) )

#define SHADOW_REPORTED_DOORLOCK_JSON   \
    "{"                             \
    "\"state\":{"                   \
    "\"reported\":{"                \
    "\"doorState\":%s,"             \
    "\"openMethod\":\"%s\","        \
    "\"doorStateChange\":%d,"       \
    "\"doorOpenMode\":%d,"          \
    "\"OTAupdate\":%d,"             \
    "\"OTAresult\":\"%s\""          \
    "}"                             \
    "}"                             \
    "}"

#define SHADOW_REPORTED_SENSOR_JSON \
    "{"                             \
    "\"state\":{"                   \
    "\"reported\":{"                \
    "\"doorState\":%s,"             \
    "\"temperature\":%.6f,"         \
    "\"battery\":%.6f"              \
    "}"                             \
    "}"                             \
    "}"

/**
 * @brief Each compilation unit that consumes the NetworkContext must define it.
 * It should contain a single pointer to the type of your desired transport.
 * When using multiple transports in the same compilation unit, define this pointer as void *.
 *
 * @note Transport stacks are defined in FreeRTOS-Plus/Source/Application-Protocols/network_transport.
 */
struct NetworkContext {
    TlsTransportParams_t *pxParams;
};

/**
 * @brief The MQTT context used for MQTT operation.
 */
static MQTTContext_t xMqttContext;

/**
 * @brief The network context used for mbedTLS operation.
 */
static NetworkContext_t xNetworkContext;

/**
 * @brief The parameters for the network context using mbedTLS operation.
 */
static TlsTransportParams_t xTlsTransportParams;

/**
 * @brief Static buffer used to hold MQTT messages being sent and received.
 */
static uint8_t ucSharedBuffer[NETWORK_BUFFER_SIZE];

/**
 * @brief Static buffer used to hold MQTT messages being sent and received.
 */
static MQTTFixedBuffer_t xBuffer = {ucSharedBuffer,
NETWORK_BUFFER_SIZE };

/**
 * @brief Static buffer used to hold MQTT messages payload to publish.
 */
static char pcPublishPayload[MAX_PUBLISH_PAYLOAD_LEN] = {0, };

// ( __USE_FLEET_PROVISION__ )
/* get from "FleetProvisioningDemoExample.c" */
/**
 * @brief Name of the provisioning template to use for the RegisterThing
 * portion of the Fleet Provisioning workflow.
 *
 * For information about provisioning templates, see the following AWS documentation:
 * https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html#fleet-provision-template
 *
 * The example template used for this demo is available in the
 * example_demo_template.json file in the demo directory. In the example,
 * replace <provisioned-thing-policy> with the policy provisioned devices
 * should have.  The demo template uses Fn::Join to construct the Thing name by
 * concatenating fp_demo_ and the serial number sent by the demo.
 *
 * @note The provisioning template MUST be created in AWS IoT before running the
 * demo.
 *
 * #define PROVISIONING_TEMPLATE_NAME    "...insert here..."
 */
#define PROVISIONING_TEMPLATE_NAME    "FleetProvisioningDemoTemplate"

/**
 * @brief The length of #PROVISIONING_TEMPLATE_NAME.
 */
#define PROVISIONING_TEMPLATE_NAME_LENGTH    ( ( uint16_t ) ( sizeof( PROVISIONING_TEMPLATE_NAME ) - 1 ) )

/**
 * @brief The length of #FP_DEMO_ID.
 */
#define FP_DEMO_ID_LENGTH                    ( ( uint16_t ) ( sizeof( FP_DEMO_ID ) - 1 ) )

/**
 * @brief Size of buffer in which to hold the certificate signing request (CSR).
 */
#define CSR_BUFFER_LENGTH                              2048
/**
 * @brief Size of buffer in which to hold the certificate.
 */
#define CERT_BUFFER_LENGTH                             2048
/**
 * @brief Size of buffer in which to hold the certificate id.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_Certificate.html#iot-Type-Certificate-certificateId
 */
#define CERT_ID_BUFFER_LENGTH                          64
/**
 * @brief Size of buffer in which to hold the certificate ownership token.
 */
#define OWNERSHIP_TOKEN_BUFFER_LENGTH                  512
/**
 * @brief Status values of the Fleet Provisioning response.
 */
typedef enum {
    ResponseNotReceived,
    ResponseAccepted,
    ResponseRejected
} ResponseStatus_t;

/**
 * @brief Status reported from the MQTT publish callback.
 */
static ResponseStatus_t xResponseStatus;

/**
 * @brief Buffer to hold responses received from the AWS IoT Fleet Provisioning
 * APIs. When the MQTT publish callback receives an expected Fleet Provisioning
 * accepted payload, it copies it into this buffer.
 */
static uint8_t pucPayloadBuffer[NETWORK_BUFFER_SIZE];

/**
 * @brief Length of the payload stored in #pucPayloadBuffer. This is set by the
 * MQTT publish callback when it copies a received payload into #pucPayloadBuffer.
 */
static size_t xPayloadLength;

static void app_provinsioning_device_service(void);
// ( __USE_FLEET_PROVISION__ )

static void prvEventCallback(MQTTContext_t *pxMqttContext, MQTTPacketInfo_t *pxPacketInfo,
    MQTTDeserializedInfo_t *pxDeserializedInfo);
static void checkCurrentDeviceStatus(app_dpm_info_rtm *_rtmData);
static bool openControl(void);
static bool closeControl(void);
static void controlDoorLock(app_dpm_info_rtm *_rtmData, INT32 _controlType, UINT8 _pubFlag);
static void connectionReadyInform(app_dpm_info_rtm *_rtmData);
static void sensorUpdate(app_dpm_info_rtm *_rtmData);
static INT32 app_parse_ota_uri(unsigned char *uri, size_t len);
static INT32 aws_dpm_app_is_connected(void);
static INT32 aws_dpm_app_subscription(void);
static void aws_dpm_app_door_work(app_dpm_info_rtm *_rtmData);
static void aws_dpm_app_sensor_work(app_dpm_info_rtm *_rtmData);
static void aws_dpm_app_init(void);
static void aws_dpm_app_connect(app_dpm_info_rtm *_rtmData);
static void aws_dpm_app_recv(app_dpm_info_rtm *_rtmData);
static void aws_dpm_app_boot(app_dpm_info_rtm *_rtmData, DM_NOTI _status);
static void aws_dpm_app_finish_loop(app_dpm_info_rtm *_rtmData);
static void aws_nodpm_app_work(app_dpm_info_rtm *_rtmData);

#if defined(__SUPPORT_OTA__)
static UINT32 aws_ota_fw_update(char *_fw_url);
#endif

/**
 * @brief JSON key for response code that indicates the type of error in
 * the error document received on topic `/delete/rejected`.
 */
#define SHADOW_DELETE_REJECTED_ERROR_CODE_KEY           "code"

/**
 * @brief Length of #SHADOW_DELETE_REJECTED_ERROR_CODE_KEY.
 */
#define SHADOW_DELETE_REJECTED_ERROR_CODE_KEY_LENGTH    ( ( uint16_t ) ( sizeof( SHADOW_DELETE_REJECTED_ERROR_CODE_KEY ) - 1 ) )

/**
 * @brief Error response code sent from AWS IoT Shadow service when an attempt
 * is made to delete a Shadow document that doesn't exist.
 */
#define SHADOW_NO_SHADOW_EXISTS_ERROR_CODE              "404"

/**
 * @brief Length of #SHADOW_NO_SHADOW_EXISTS_ERROR_CODE.
 */
#define SHADOW_NO_SHADOW_EXISTS_ERROR_CODE_LENGTH       ( ( uint16_t ) ( sizeof( SHADOW_NO_SHADOW_EXISTS_ERROR_CODE ) - 1 ) )

/**
 * @brief When we send an update to the device shadow, and if we care about
 * the response from cloud (accepted/rejected), remember the clientToken and
 * use it to match with the response.
 */
static uint32_t ulClientToken = 0U;

/**
 * @brief The return status of prvUpdateAcceptedHandler callback function.
 */
static BaseType_t xUpdateAcceptedReturn = pdPASS;

/**
 * @brief Status of the response of Shadow delete operation from AWS IoT
 * message broker.
 */
static BaseType_t xDeleteResponseReceived = pdFALSE;

/**
 * @brief Status of the Shadow delete operation.
 *
 * The Shadow delete status will be updated by the incoming publishes on the
 * MQTT topics for delete acknowledgement from AWS IoT message broker
 * (accepted/rejected). Shadow document is considered to be deleted if an
 * incoming publish is received on `/delete/accepted` topic or an incoming
 * publish is received on `/delete/rejected` topic with error code 404. Code 404
 * indicates that the Shadow document does not exist for the Thing yet.
 */
static BaseType_t xShadowDeleted = pdFALSE;

static void prvDeleteRejectedHandler(MQTTPublishInfo_t *pxPublishInfo);
static void prvUpdateDeltaHandler(MQTTPublishInfo_t *pxPublishInfo);
static void prvUpdateAcceptedHandler(MQTTPublishInfo_t *pxPublishInfo);

/*-----------------------------------------------------------*/
/**
 * @brief The JSON key of the execution object.
 *
 * Job documents received from the AWS IoT Jobs service are in JSON format.
 * All such JSON documents will contain this key, whose value represents the unique
 * identifier of a Job.
 */
#define jobsexampleEXECUTION_KEY                    "execution"

/**
 * @brief The length of #jobsexampleEXECUTION_KEY.
 */
#define jobsexampleEXECUTION_KEY_LENGTH             ( sizeof( jobsexampleEXECUTION_KEY ) - 1 )

/**
 * @brief The query key to use for searching the Job ID key in message payload
 * from AWS IoT Jobs service.
 *
 * Job documents received from the AWS IoT Jobs service are in JSON format.
 * All such JSON documents will contain this key, whose value represents the unique
 * identifier of a Job.
 */
#define jobsexampleQUERY_KEY_FOR_JOB_ID             jobsexampleEXECUTION_KEY  ".jobId"

/**
 * @brief The length of #jobsexampleQUERY_KEY_FOR_JOB_ID.
 */
#define jobsexampleQUERY_KEY_FOR_JOB_ID_LENGTH      ( sizeof( jobsexampleQUERY_KEY_FOR_JOB_ID ) - 1 )

/**
 * @brief The query key to use for searching the Jobs document ID key in message payload
 * from AWS IoT Jobs service.
 *
 * Job documents received from the AWS IoT Jobs service are in JSON format.
 * All such JSON documents will contain this key, whose value represents the unique
 * identifier of a Job.
 */
#define jobsexampleQUERY_KEY_FOR_JOBS_DOC           jobsexampleEXECUTION_KEY  ".jobDocument"

/**
 * @brief The length of #jobsexampleQUERY_KEY_FOR_JOBS_DOC.
 */
#define jobsexampleQUERY_KEY_FOR_JOBS_DOC_LENGTH    ( sizeof( jobsexampleQUERY_KEY_FOR_JOBS_DOC ) - 1 )

/**
 * @brief The query key to use for searching the Action key in Jobs document
 * from AWS IoT Jobs service.
 *
 * This demo program expects this key to be in the Job document. It is a key
 * specific to this demo.
 */
#define jobsexampleQUERY_KEY_FOR_ACTION             "operation"
#define jobsexampleQUERY_KEY_FOR_SOURCE_LINK        "Source"
#define jobsexampleQUERY_KEY_FOR_SOURCE_LINK_LENGTH ( sizeof( jobsexampleQUERY_KEY_FOR_SOURCE_LINK ) - 1 )

/**
 * @brief The length of #jobsexampleQUERY_KEY_FOR_ACTION.
 */
#define jobsexampleQUERY_KEY_FOR_ACTION_LENGTH      ( sizeof( jobsexampleQUERY_KEY_FOR_ACTION ) - 1 )

/**
 * @brief The query key to use for searching the Message key in Jobs document
 * from AWS IoT Jobs service.
 *
 * This demo program expects this key to be in the Job document if the "action"
 * is either "publish" or "print". It represents the message that should be
 * published or printed, respectively.
 */
#define jobsexampleQUERY_KEY_FOR_MESSAGE            "message"

/**
 * @brief The length of #jobsexampleQUERY_KEY_FOR_MESSAGE.
 */
#define jobsexampleQUERY_KEY_FOR_MESSAGE_LENGTH     ( sizeof( jobsexampleQUERY_KEY_FOR_MESSAGE ) - 1 )

/**
 * @brief The query key to use for searching the topic key in Jobs document
 * from AWS IoT Jobs service.
 *
 * This demo program expects this key to be in the Job document if the "action"
 * is "publish". It represents the MQTT topic on which the message should be
 * published.
 */
#define jobsexampleQUERY_KEY_FOR_TOPIC              "topic"

/**
 * @brief The length of #jobsexampleQUERY_KEY_FOR_TOPIC.
 */
#define jobsexampleQUERY_KEY_FOR_TOPIC_LENGTH       ( sizeof( jobsexampleQUERY_KEY_FOR_TOPIC ) - 1 )

/**
 * @brief Utility macro to generate the PUBLISH topic string to the
 * DescribeJobExecution API of AWS IoT Jobs service for requesting
 * the next pending job information.
 *
 * @param[in] thingName The name of the Thing resource to query for the
 * next pending job.
 */
#define DESCRIBE_NEXT_JOB_TOPIC( thingName ) \
    ( JOBS_API_PREFIX thingName JOBS_API_BRIDGE JOBS_API_JOBID_NEXT "/" JOBS_API_GETPENDING )

/**
 * @brief Utility macro to generate the subscription topic string for the
 * NextJobExecutionChanged API of AWS IoT Jobs service that is required
 * for getting notification about changes in the next pending job in the queue.
 *
 * @param[in] thingName The name of the Thing resource to query for the
 * next pending Job.
 */
#define NEXT_JOB_EXECUTION_CHANGED_TOPIC( thingName ) \
    ( JOBS_API_PREFIX thingName JOBS_API_BRIDGE JOBS_API_NEXTJOBCHANGED )

/**
 * @brief Format a JSON status message.
 *
 * @param[in] x one of "IN_PROGRESS", "SUCCEEDED", or "FAILED"
 */
#define MAKE_STATUS_REPORT( x )    "{\"status\":\"" x "\"}"

/**
 * @brief Time in ticks to wait between retries of the demo loop if
 * demo loop fails.
 */
#define DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_TICKS    ( pdMS_TO_TICKS( 5000U ) )

/*-----------------------------------------------------------*/

/**
 * @brief Currently supported actions that a job document can specify.
 */
typedef enum JobActionType {
    JOB_ACTION_PRINT, /**< Print a message. */
    JOB_ACTION_PUBLISH, /**< Publish a message to an MQTT topic. */
    JOB_ACTION_EXIT, /**< Exit the demo. */
    JOB_ACTION_INSTALL, /**< Install the linked firmware */
    JOB_ACTION_UNKNOWN /**< Unknown action. */
} JobActionType;

/**
 * @brief Static buffer used to hold the job ID of the single job that
 * is executed at a time in the demo. This buffer allows re-use of the MQTT
 * connection context for sending status updates of a job while it is being
 * processed.
 */
static uint8_t usJobIdBuffer[1024];

/**
 * @brief Static buffer used to hold the job document of the single job that
 * is executed at a time in the demo. This buffer allows re-use of the MQTT
 * connection context for sending status updates of a job while it is being processed.
 */
static uint8_t usJobsDocumentBuffer[1024];

/**
 * @brief A global flag which represents whether an error was encountered while
 * executing the demo.
 *
 * @note When this flag is set, the demo terminates execution.
 */
static BaseType_t xDemoEncounteredError = pdFALSE;

/*-----------------------------------------------------------*/

/**
 * @brief Converts a string in a job document to a #JobActionType
 * value.
 *
 * @param[in] pcAction The job action as a string.
 * @param[in] xActionLength The length of @p pcAction.
 *
 * @return A #JobActionType equivalent to the given string.
 */
static JobActionType prvGetAction(const char *pcAction, size_t xActionLength);

/**
 * @brief Process payload from NextJobExecutionChanged and DescribeJobExecution
 * API MQTT topics of AWS IoT Jobs service.
 *
 * This handler parses the received payload about the next pending job, identifies
 * the action requested in the job document, and executes the action.
 *
 * @param[in] pPublishInfo Deserialized publish info pointer for the incoming
 * packet.
 */
static void prvNextJobHandler(MQTTPublishInfo_t *pxPublishInfo);

/**
 * @brief Sends an update for a job to the UpdateJobExecution API of the AWS IoT Jobs service.
 *
 * @param[in] pcJobId The job ID whose status has to be updated.
 * @param[in] usJobIdLength The length of the job ID string.
 * @param[in] pcJobStatusReport The JSON formatted report to send to the AWS IoT Jobs service
 * to update the status of @p pcJobId.
 */
static void prvSendUpdateForJob(char *pcJobId, uint16_t usJobIdLength, const char *pcJobStatusReport);

/**
 * @brief Executes a job received from AWS IoT Jobs service and sends an update back to the service.
 * It parses the received job document, executes the job depending on the job "Action" type, and
 * sends an update to AWS for the Job.
 *
 * @param[in] pcJobId The ID of the job to execute.
 * @param[in] usJobIdLength The length of the job ID string.
 * @param[in] pcJobDocument The JSON document associated with the @a pcJobID job
 * that is to be processed.
 * @param[in] usDocumentLength The length of the job document.
 */
static void prvProcessJobDocument(char *pcJobId, uint16_t usJobIdLength, char *pcJobDocument,
    uint16_t jobDocumentLength);

/*-----------------------------------------------------------*/
#define MAX_RTM_FLOAT_STRING				18

typedef struct CLIENT_SAMPLE_INFO_TAG {
    unsigned int sleep_time;
    char *iothub_uri;
    char *access_key_name;
    char *device_key;
    char *device_id;
    int registration_complete;
} CLIENT_SAMPLE_INFO;

static bool xAppConnectionEstablished = false;
static MQTTStatus_t commonRC = MQTTSuccess;
static bool updateSensorFlag = false;
static bool controlFlag = false;
static bool connectFlag = false;
static int doorLock = Door_Idle; // 0 = idle, 1 = open, 2 = close, 3 = auto close by timer 10 sec.
static bool doorOpenFlag = false;
static int doorStateChange = 0;		// int 1 = changed, 0 = not changed
static int doorOpenMode = 0;			// 0 = auto, 1 = manual 
static char currentOTAResult[20] = {0, };	// "OTA_OK", "OTA_NG", "OTA_UNKNOWN"
static char currentOpenMethod[10] = {0, };	// "keypad", "mcu", "app"

static UINT8 aws_file_url[MAX_URL_LEN] = {0, };
//static char ota_path_url_rtos[MAX_URL_LEN] = {0, };//[tin aws work]

static float currentTemperature = (float)INIT_SENSOR_VAL_4B;
static float currentBattery = (float)INIT_SENSOR_VAL_4B;

#if defined (__BLE_COMBO_REF__) //da16600work
static char ota_path_url_ble[MAX_URL_LEN] = { 0, };
extern uint32_t wifi_svc_get_provisioning_flag(void);
#endif

// extern unsigned int da16x_ping_client(int, char*, unsigned long, unsigned long*, unsigned long*, int, unsigned long,
//     int, int, int, char*);

extern UINT	rrq61x_ping_client(int iface,
							char *domain_str,
							unsigned long ipaddr,
							unsigned long *ipv6dst,
							unsigned long *ipv6src,
							int len,
							unsigned long count,
							int wait,
							int interval,
							int nodisplay,
							char *ping_result);

extern void reboot_func(UINT flag);//[tin aws work]
extern int getMacAddrMswLsw(UINT iface, ULONG *macmsw, ULONG *maclsw);//[tin aws work]

MQTTContext_t* app_get_mqtt_context(void)
{
    uint16_t context_check = 0;
    retry: if (xMqttContext.connectStatus == MQTTNotConnected) {
        if (context_check < 20) {
            context_check++;
            vTaskDelay(5);
            goto retry;
        }
    }
    return &xMqttContext;
}

MQTTStatus_t app_get_mqtt_status(void)
{
    return commonRC;
}

char* app_get_ota_url(void)
{
    return (char*)aws_file_url;
}

char* app_get_ota_result(void)
{
    return currentOTAResult;
}

void app_set_mqtt_status(MQTTStatus_t rc)
{
    commonRC = rc;
    return;
}

void app_aws_dpm_app_connect(app_dpm_info_rtm *_rtmData)
{
    aws_dpm_app_connect(_rtmData);
}

static void prvEventCallback(MQTTContext_t *pxMqttContext, MQTTPacketInfo_t *pxPacketInfo,
    MQTTDeserializedInfo_t *pxDeserializedInfo)
{
    ShadowMessageType_t messageType = ShadowMessageTypeMaxNum;
    const char *pcThingName = NULL;
    uint8_t ucThingNameLength = 0U;
    const char *pcShadowName = NULL;
    uint8_t ucShadowNameLength = 0U;
    uint16_t usPacketIdentifier;
    JobsTopic_t topicType = JobsMaxTopic;
    char regThingName[MAX_THING_NAME_LENGTH] = {0, };
    size_t lenRegThingName = 0;

    (void)pxMqttContext;

    configASSERT(pxDeserializedInfo != NULL);
    configASSERT(pxMqttContext != NULL);
    configASSERT(pxPacketInfo != NULL);

    usPacketIdentifier = pxDeserializedInfo->packetIdentifier;

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if ((pxPacketInfo->type & 0xF0U) == MQTT_PACKET_TYPE_PUBLISH) {

        configASSERT(pxDeserializedInfo->pPublishInfo != NULL);

        memset(regThingName, 0, sizeof(regThingName));
        strcpy(regThingName, app_get_registered_thing_name());

        lenRegThingName = strlen(regThingName);

        if (lenRegThingName == 0) {
            LogError(("registered thing name invalid!!!"));
            //ToDo::exception process
        }

        //==command topic
        /* Verify the received publish is for the we have subscribed to. */
        if ((pxDeserializedInfo->pPublishInfo->topicNameLength == strlen(getAWSCommandSubName()))
            && (0
                == strncmp(getAWSCommandSubName(), pxDeserializedInfo->pPublishInfo->pTopicName,
                    pxDeserializedInfo->pPublishInfo->topicNameLength)) && (getOTAStat() != OTA_STAT_JOB_CONFIRMED)) {
            LogInfo( ( "\r\nIncoming Publish Topic Name: (Command) %.*s matches subscribed topic.\r\n"
                    "Incoming Publish Message : %.*s\r\n",
                    pxDeserializedInfo->pPublishInfo->topicNameLength,
                    pxDeserializedInfo->pPublishInfo->pTopicName,
                    pxDeserializedInfo->pPublishInfo->payloadLength,
                    (char*)pxDeserializedInfo->pPublishInfo->pPayload ) );
            if (pal_app_event_cb((char*)pxDeserializedInfo->pPublishInfo->pPayload,
                (int32_t)pxDeserializedInfo->pPublishInfo->payloadLength, &connectFlag, &controlFlag, &updateSensorFlag)) {
                return;
            } else if (strncmp((char*)pxDeserializedInfo->pPublishInfo->pPayload, AWS_CONTROL_OPEN,
                strlen(AWS_CONTROL_OPEN)) == 0 && controlFlag == false) {
                IOT_INFO("open comm")
                controlFlag = true;
                doorLock = Door_Open;
            } else if (strncmp((char*)pxDeserializedInfo->pPublishInfo->pPayload, AWS_CONTROL_CLOSE,
                strlen(AWS_CONTROL_CLOSE)) == 0 && controlFlag == false) {
                IOT_INFO("close comm")
                controlFlag = true;
                doorLock = Door_Close;
            } else if (strncmp((char*)pxDeserializedInfo->pPublishInfo->pPayload, AWS_CONTROL_OTA,
                strlen(AWS_CONTROL_OTA)) == 0) {
                IOT_INFO("confirmOTA comm")
                setOTAStat(OTA_STAT_JOB_CONFIRMED);
            } else if (strncmp((char*)pxDeserializedInfo->pPublishInfo->pPayload,
            AWS_CONTROL_SENSOR, strlen(AWS_CONTROL_SENSOR)) == 0) //internal sensor such as battery and temperature
                {
                IOT_INFO("updateSensor comm")
                updateSensorFlag = true;
                doorLock = Door_Idle;
            } else if (strncmp((char*)pxDeserializedInfo->pPublishInfo->pPayload,
            AWS_CONTROL_CONNECT, strlen(AWS_CONTROL_CONNECT)) == 0 && connectFlag == false) // connected
            {
                IOT_INFO("connect comm")
                doorLock = Door_Idle;
                connectFlag = true;
            }
            app_print_elapse_time_ms("[%s:%d]", __func__, __LINE__);
        }
        //==jobs topic
        /* Let the Jobs library tell us whether this is a Jobs message. */
        else if (JobsSuccess
            == Jobs_MatchTopic((char*)pxDeserializedInfo->pPublishInfo->pTopicName,
                pxDeserializedInfo->pPublishInfo->topicNameLength, regThingName, (uint16_t)lenRegThingName, &topicType,
                NULL,
                NULL)) {
            app_print_elapse_time_ms("[%s:%d] ===> topicType = %d", __func__, __LINE__, topicType);
            LogInfo( ( "\r\nIncoming Publish Topic Name: (Jobs) %.*s matches subscribed topic.\r\n"
                    "Incoming Publish Message : %.*s\r\n",
                    pxDeserializedInfo->pPublishInfo->topicNameLength,
                    pxDeserializedInfo->pPublishInfo->pTopicName,
                    pxDeserializedInfo->pPublishInfo->payloadLength,
                    (char *)pxDeserializedInfo->pPublishInfo->pPayload ) );
//awsupgradeport[[::awsdpmwork
            if (dpm_mode_is_enabled()) {
                if (topicType == JobsUpdateSuccess || topicType == JobsUpdateFailed) {
                    app_dpm_set_wait_job_next_flag(1);
                } else if (/*topicType == JobsDescribeSuccess || */topicType == JobsNextJobChanged) {
                    app_dpm_set_wait_job_next_flag(0);
                }
            }
//]]
            /* Upon successful return, the messageType has been filled in. */
            if ((topicType == JobsDescribeSuccess) || (topicType == JobsNextJobChanged)) {
                /* Handler function to process payload. */
                prvNextJobHandler(pxDeserializedInfo->pPublishInfo);
            } else if (topicType == JobsUpdateSuccess) {
                LogInfo( ( "Job update status request has been accepted by AWS Iot Jobs service." ) );
            } else if (topicType == JobsStartNextFailed) {
                LogWarn( ( "Request for next job description rejected: RejectedResponse=%.*s.",
                        pxDeserializedInfo->pPublishInfo->payloadLength,
                        ( const char * ) pxDeserializedInfo->pPublishInfo->pPayload ) );
            } else if (topicType == JobsUpdateFailed) {
                /* Set the global flag to terminate the demo, because the request for updating and executing the job status
                 * has been rejected by the AWS IoT Jobs service. */
                xDemoEncounteredError = pdTRUE;

                LogWarn( ( "Request for job update rejected: RejectedResponse=%.*s.",
                        pxDeserializedInfo->pPublishInfo->payloadLength,
                        ( const char * ) pxDeserializedInfo->pPublishInfo->pPayload ) );

                LogError( ( "Terminating demo as request to update job status has been rejected by "
                        "AWS IoT Jobs service..." ) );
            } else {
                LogWarn( ( "Received an unexpected messages from AWS IoT Jobs service: "
                        "JobsTopicType=%u", topicType ) );
            }
        }
        //==shadow topic
        /* Let the Device Shadow library tell us whether this is a device shadow message. */
        else if (SHADOW_SUCCESS
            == Shadow_MatchTopicString(pxDeserializedInfo->pPublishInfo->pTopicName,
                pxDeserializedInfo->pPublishInfo->topicNameLength, &messageType, &pcThingName, &ucThingNameLength,
                &pcShadowName, &ucShadowNameLength) && (getOTAStat() == OTA_STAT_JOB_NONE)) {
            LogInfo( ( "\r\nIncoming Publish Topic Name: (Shadow) %.*s matches subscribed topic.\r\n"
                    "Incoming Publish Message : %.*s\r\n",
                    pxDeserializedInfo->pPublishInfo->topicNameLength,
                    pxDeserializedInfo->pPublishInfo->pTopicName,
                    pxDeserializedInfo->pPublishInfo->payloadLength,
                    (char *)pxDeserializedInfo->pPublishInfo->pPayload ) );
            /* Upon successful return, the messageType has been filled in. */
            if (messageType == ShadowMessageTypeUpdateDelta) {
                /* Handler function to process payload. */
                prvUpdateDeltaHandler(pxDeserializedInfo->pPublishInfo);
            } else if (messageType == ShadowMessageTypeUpdateAccepted) {
                /* Handler function to process payload. */
                prvUpdateAcceptedHandler(pxDeserializedInfo->pPublishInfo);
            } else if (messageType == ShadowMessageTypeUpdateDocuments) {
                LogInfo( ( "/update/documents json payload:%s.", ( const char * ) pxDeserializedInfo->pPublishInfo->pPayload ) );
            } else if (messageType == ShadowMessageTypeUpdateRejected) {
                LogInfo( ( "/update/rejected json payload:%s.", ( const char * ) pxDeserializedInfo->pPublishInfo->pPayload ) );
            } else if (messageType == ShadowMessageTypeDeleteAccepted) {
                LogInfo( ( "Received an MQTT incoming publish on /delete/accepted topic." ) );
                xShadowDeleted = pdTRUE;
                xDeleteResponseReceived = pdTRUE;
            } else if (messageType == ShadowMessageTypeDeleteRejected) {
                /* Handler function to process payload. */
                prvDeleteRejectedHandler(pxDeserializedInfo->pPublishInfo);
                xDeleteResponseReceived = pdTRUE;
            } else {
                LogInfo( ( "Other message type:%d !!", messageType ) );
            }
        } else {
            LogError( ( "TopicString parse failed:%s !!", ( const char * ) pxDeserializedInfo->pPublishInfo->pTopicName ) );
        }
    } else {
        vHandleOtherIncomingPacket(pxPacketInfo, usPacketIdentifier);
    }
}

static JobActionType prvGetAction(const char *pcAction, size_t xActionLength)
{
    JobActionType xAction = JOB_ACTION_UNKNOWN;

    configASSERT(pcAction != NULL);

    if (strncmp(pcAction, "install", xActionLength) == 0) {
        xAction = JOB_ACTION_INSTALL;
    }

    return xAction;
}

static void prvSendUpdateForJob(char *pcJobId, uint16_t usJobIdLength, const char *pcJobStatusReport)
{
    size_t ulTopicLength = 0;
    JobsStatus_t xStatus = JobsSuccess;
    char regThingName[MAX_THING_NAME_LENGTH] = {0, };
    size_t lenRegThingName = 0;

    configASSERT(( pcJobId != NULL ) && ( usJobIdLength > 0 ));
    configASSERT(pcJobStatusReport != NULL);

    memset(regThingName, 0, sizeof(regThingName));
    strcpy(regThingName, app_get_registered_thing_name());

    lenRegThingName = strlen(regThingName);

    char pUpdateJobTopic[JOBS_API_MAX_LENGTH(lenRegThingName)];

    if (lenRegThingName == 0) {
        LogError(("registered thing name invalid!!!"));
        xStatus = JobsError;
        //ToDo::exception process
    } else {
        /* Generate the PUBLISH topic string for the UpdateJobExecution API of AWS IoT Jobs service. */
        xStatus = Jobs_Update(pUpdateJobTopic, sizeof(pUpdateJobTopic), regThingName, (uint16_t)lenRegThingName, pcJobId,
            usJobIdLength, &ulTopicLength);
    }

    if (xStatus == JobsSuccess) {
        if (xPublishToTopic(&xMqttContext, pUpdateJobTopic, (int32_t)ulTopicLength, pcJobStatusReport,
            strlen(pcJobStatusReport)) == pdFALSE) {
            /* Set global flag to terminate demo as PUBLISH operation to update job status failed. */
            xDemoEncounteredError = pdTRUE;

            LogError( ( "Failed to update the status of job: JobID=%.*s, NewStatePayload=%s",
                    usJobIdLength, pcJobId, pcJobStatusReport ) );
        }
    } else {
        /* Set global flag to terminate demo as topic generation for UpdateJobExecution API failed. */
        xDemoEncounteredError = pdTRUE;

        LogError( ( "Failed to generate Publish topic string for sending job update: "
                "JobID=%.*s, NewStatePayload=%s",
                usJobIdLength, pcJobId, pcJobStatusReport ) );
    }
}

static void prvProcessJobDocument(char *pcJobId, uint16_t usJobIdLength, char *pcJobDocument,
    uint16_t jobDocumentLength)
{
    char *pcAction = NULL;
    size_t uActionLength = 0U;
    JSONStatus_t xJsonStatus = JSONSuccess;

    configASSERT(pcJobId != NULL);
    configASSERT(usJobIdLength > 0);
    configASSERT(pcJobDocument != NULL);
    configASSERT(jobDocumentLength > 0);

    xJsonStatus = JSON_Search(pcJobDocument, jobDocumentLength, jobsexampleQUERY_KEY_FOR_ACTION,
        jobsexampleQUERY_KEY_FOR_ACTION_LENGTH, &pcAction, &uActionLength);

    if (xJsonStatus != JSONSuccess) {
        LogError( ( "Job document schema is invalid. Missing expected \"action\" key in document." ) );
        prvSendUpdateForJob(pcJobId, usJobIdLength, MAKE_STATUS_REPORT("FAILED"));
    } else {
        JobActionType xActionType = JOB_ACTION_UNKNOWN;

        xActionType = prvGetAction(pcAction, uActionLength);

        switch (xActionType) {
        case JOB_ACTION_INSTALL:
            LogInfo( ( "Received job contains \"install\" action." ) );
            char *pcSourceLink = NULL;
            size_t ulSourceLinkLength = 0U;
            INT32 rcode;

            xJsonStatus = JSON_Search(pcJobDocument, jobDocumentLength, jobsexampleQUERY_KEY_FOR_SOURCE_LINK,
                jobsexampleQUERY_KEY_FOR_SOURCE_LINK_LENGTH, &pcSourceLink, &ulSourceLinkLength);

            if (xJsonStatus == JSONSuccess) {
                /* Print the given message if the action is "print". */
                LogInfo( ( "\r\n"
                        "/*-----------------------------------------------------------*/\r\n"
                        "\r\n"
                        "%.*s\r\n"
                        "\r\n"
                        "/*-----------------------------------------------------------*/\r\n"
                        "\r\n", ulSourceLinkLength, pcSourceLink ) );
                setOTAStat(OTA_STAT_JOB_READY);
                memset(aws_file_url, 0, sizeof(aws_file_url));
                memcpy(aws_file_url, pcSourceLink, ulSourceLinkLength);
                IOT_INFO("aws f/w url: %s", aws_file_url)
                rcode = api_usr_nvram_write_string(AWS_NVRAM_CONFIG_OTA_URL, (const char*)aws_file_url);
                vTaskDelay(3);
                if (rcode) {
                    LogError(("write AWS_NVRAM_CONFIG_OTA_URL failed"));
                    vTaskDelay(3);
                }
                prvSendUpdateForJob(pcJobId, usJobIdLength, MAKE_STATUS_REPORT("SUCCEEDED"));
                break;
            } else {
                LogError( ( "Job document schema is invalid. Missing \"Source\" for \"install\" action type." ) );
                prvSendUpdateForJob(pcJobId, usJobIdLength, MAKE_STATUS_REPORT("FAILED"));
            }

            break;

        default:
            LogInfo( ( "Received Job document with unknown action %.*s.",
                    uActionLength, pcAction ) );
            break;
        }
    }
}

static void prvNextJobHandler(MQTTPublishInfo_t *pxPublishInfo)
{
    configASSERT(pxPublishInfo != NULL);
    configASSERT(( pxPublishInfo->pPayload != NULL ) && ( pxPublishInfo->payloadLength > 0 ));

    /* Check validity of JSON message response from server.*/
    if (JSON_Validate(pxPublishInfo->pPayload, pxPublishInfo->payloadLength) != JSONSuccess) {
        LogError( ( "Received invalid JSON payload from AWS IoT Jobs service" ) );
    } else {
        char *pcJobId = NULL;
        size_t ulJobIdLength = 0UL;

        /* Parse the Job ID of the next pending job execution from the JSON payload. */
        if ( JSON_Search( ( char * ) pxPublishInfo->pPayload,
            pxPublishInfo->payloadLength,
            jobsexampleQUERY_KEY_FOR_JOB_ID,
            jobsexampleQUERY_KEY_FOR_JOB_ID_LENGTH,
            &pcJobId,
            &ulJobIdLength ) != JSONSuccess) {
            LogWarn( ( "Failed to parse Job ID in message received from AWS IoT Jobs service: "
                    "IncomingTopic=%.*s, Payload=%.*s",
                    pxPublishInfo->topicNameLength, pxPublishInfo->pTopicName,
                    pxPublishInfo->payloadLength, (char *)pxPublishInfo->pPayload ) );
        } else {
            char *pcJobDocLoc = NULL;
            size_t ulJobDocLength = 0UL;

            configASSERT(ulJobIdLength < JOBS_JOBID_MAX_LENGTH);LogInfo( ( "Received a Job from AWS IoT Jobs service: JobId=%.*s",
                    ulJobIdLength, pcJobId ) );

            /* Copy the Job ID in the global buffer. This is done so that
             * the MQTT context's network buffer can be used for sending jobs
             * status updates to the AWS IoT Jobs service. */
            memcpy(usJobIdBuffer, pcJobId, ulJobIdLength);

            /* Search for the jobs document in the payload. */
            if ( JSON_Search( ( char * ) pxPublishInfo->pPayload,
                pxPublishInfo->payloadLength,
                jobsexampleQUERY_KEY_FOR_JOBS_DOC,
                jobsexampleQUERY_KEY_FOR_JOBS_DOC_LENGTH,
                &pcJobDocLoc,
                &ulJobDocLength ) != JSONSuccess) {
                LogWarn( ( "Failed to parse document of next job received from AWS IoT Jobs service: "
                        "Topic=%.*s, JobID=%.*s",
                        pxPublishInfo->topicNameLength, pxPublishInfo->pTopicName,
                        ulJobIdLength, pcJobId ) );
            } else {
                /* Copy the Job document in buffer. This is done so that the MQTT connection buffer can
                 * be used for sending jobs status updates to the AWS IoT Jobs service. */
                memcpy(usJobsDocumentBuffer, pcJobDocLoc, ulJobDocLength);

                /* Process the Job document and execute the job. */
                prvProcessJobDocument((char*)usJobIdBuffer, (uint16_t)ulJobIdLength, (char*)usJobsDocumentBuffer,
                    (uint16_t)ulJobDocLength);
            }
        }
    }
}

static void prvDeleteRejectedHandler(MQTTPublishInfo_t *pxPublishInfo)
{
    JSONStatus_t result = JSONSuccess;
    char *pcOutValue = NULL;
    uint32_t ulOutValueLength = 0UL;

    configASSERT(pxPublishInfo != NULL);
    configASSERT(pxPublishInfo->pPayload != NULL);

    LogInfo( ( "/delete/rejected json payload:%s.", ( const char * ) pxPublishInfo->pPayload ) );

    /* The payload will look similar to this:
     * {
     *    "code": error-code,
     *    "message": "error-message",
     *    "timestamp": timestamp,
     *    "clientToken": "token"
     * }
     */

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate(pxPublishInfo->pPayload, pxPublishInfo->payloadLength);

    if (result == JSONSuccess) {
        /* Then we start to get the version value by JSON keyword "version". */
        result = JSON_SearchConst(pxPublishInfo->pPayload, pxPublishInfo->payloadLength,
        SHADOW_DELETE_REJECTED_ERROR_CODE_KEY,
        SHADOW_DELETE_REJECTED_ERROR_CODE_KEY_LENGTH, (const char**)&pcOutValue, (size_t*)&ulOutValueLength,
        NULL);
    } else {
        LogError( ( "The json document is invalid!!" ) );
    }

    if (result == JSONSuccess) {
        LogInfo( ( "Error code is: %.*s.",
                (int)ulOutValueLength,
                pcOutValue ) );

        /* Check if error code is `404`. An error code `404` indicates that an
         * attempt was made to delete a Shadow document that didn't exist. */
        if (ulOutValueLength == SHADOW_NO_SHADOW_EXISTS_ERROR_CODE_LENGTH) {
            if (strncmp(pcOutValue, SHADOW_NO_SHADOW_EXISTS_ERROR_CODE,
            SHADOW_NO_SHADOW_EXISTS_ERROR_CODE_LENGTH) == 0) {
                xShadowDeleted = pdTRUE;
            }
        }
    } else {
        LogError( ( "No error code in json document!!" ) );
    }
}

static void prvUpdateDeltaHandler(MQTTPublishInfo_t *pxPublishInfo)
{
    static uint32_t ulCurrentVersion = 0; /* Remember the latestVersion # we've ever received */
    uint32_t ulVersion = 0U;
    char *pcOutValue = NULL;
    uint32_t ulOutValueLength = 0U;
    JSONStatus_t result = JSONSuccess;

    configASSERT(pxPublishInfo != NULL);
    configASSERT(pxPublishInfo->pPayload != NULL);

    LogInfo( ( "/update/delta json payload:%s.", ( const char * ) pxPublishInfo->pPayload ) );

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate(pxPublishInfo->pPayload, pxPublishInfo->payloadLength);

    if (result == JSONSuccess) {
        /* Then we start to get the version value by JSON keyword "version". */
        result = JSON_Search((char* ) pxPublishInfo->pPayload, pxPublishInfo->payloadLength, "version",
            sizeof("version") - 1, &pcOutValue, (size_t* ) &ulOutValueLength);
    } else {
        LogError( ( "The json document is invalid!!" ) );
    }

    if (result == JSONSuccess) {
        LogInfo( ( "version: %.*s",
                (int)ulOutValueLength,
                pcOutValue ) );

        /* Convert the extracted value to an unsigned integer value. */
        ulVersion = (uint32_t)strtoul(pcOutValue, NULL, 10);
    } else {
        LogError( ( "No version in json document!!" ) );
    }

    LogInfo( ( "version:%lu, ulCurrentVersion:%lu \r\n", ulVersion, ulCurrentVersion ) );

    /* When the version is much newer than the one we retained, that means the powerOn
     * state is valid for us. */
    if (ulVersion > ulCurrentVersion) {
        /* Set to received version as the current version. */
        ulCurrentVersion = ulVersion;

    } else {
        /* In this demo, we discard the incoming message
         * if the version number is not newer than the latest
         * that we've received before. Your application may use a
         * different approach.
         */
        LogWarn( ( "The received version is smaller than current one!!" ) );
    }
}

static void prvUpdateAcceptedHandler(MQTTPublishInfo_t *pxPublishInfo)
{
    char *pcOutValue = NULL;
    uint32_t ulOutValueLength = 0U;
    uint32_t ulReceivedToken = 0U;
    JSONStatus_t result = JSONSuccess;

    configASSERT(pxPublishInfo != NULL);
    configASSERT(pxPublishInfo->pPayload != NULL);

    LogInfo( ( "/update/accepted json payload:%s.", ( const char * ) pxPublishInfo->pPayload ) );

    /* Handle the reported state with state change in /update/accepted topic.
     * Thus we will retrieve the client token from the json document to see if
     * it's the same one we sent with reported state on the /update topic.
     * The payload will look similar to this:
     *  {
     *      "state": {
     *          "reported": {
     *          "powerOn": 1
     *          }
     *      },
     *      "metadata": {
     *          "reported": {
     *          "powerOn": {
     *              "timestamp": 1596573647
     *          }
     *          }
     *      },
     *      "version": 14698,
     *      "timestamp": 1596573647,
     *      "clientToken": "022485"
     *  }
     */

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate(pxPublishInfo->pPayload, pxPublishInfo->payloadLength);

    if (result == JSONSuccess) {
        /* Get clientToken from json documents. */
        result = JSON_Search((char* ) pxPublishInfo->pPayload, pxPublishInfo->payloadLength, "clientToken",
            sizeof("clientToken") - 1, &pcOutValue, (size_t* ) &ulOutValueLength);
    } else {
        LogError( ( "Invalid json documents !!" ) );
    }

    if (result == JSONSuccess) {
        LogInfo( ( "clientToken: %.*s", (int)ulOutValueLength,
                pcOutValue ) );

        /* Convert the code to an unsigned integer value. */
        ulReceivedToken = (uint32_t)strtoul(pcOutValue, NULL, 10);

        LogInfo( ( "receivedToken:%lu, clientToken:%lu \r\n", ulReceivedToken, ulClientToken ) );

        /* If the clientToken in this update/accepted message matches the one we
         * published before, it means the device shadow has accepted our latest
         * reported state. We are done. */
        if (ulReceivedToken == ulClientToken) {
            LogInfo( ( "Received response from the device shadow. Previously published "
                    "update with clientToken=%lu has been accepted. ", ulClientToken ) );
        } else {
            LogWarn( ( "The received clientToken=%lu is not identical with the one=%lu we sent ",
                    ulReceivedToken, ulClientToken ) );
        }
    } else {
        LogError( ( "No clientToken in json document!!" ) );
        xUpdateAcceptedReturn = pdFAIL;
    }
}

static void checkCurrentDeviceStatus(app_dpm_info_rtm *_rtmData)
{
    app_dpm_info_rtm *data = (app_dpm_info_rtm*)_rtmData;

    char tTemp[MAX_RTM_FLOAT_STRING] = {0, };
    char tBat[MAX_RTM_FLOAT_STRING] = {0, };

    if (data == NULL) {
        IOT_INFO("no RTM data..")
        return;
    }

    if (data->doorOpen == true) {
        doorOpenFlag = true;
    }
    currentTemperature = (float)INIT_SENSOR_VAL_4B;
    //data->temperature = INIT_SENSOR_VAL_4B;
    sprintf(tTemp, "%.6f", (double)data->temperature);//[tin aws work]

    currentBattery = (float)INIT_SENSOR_VAL_4B;
    //data->battery= INIT_SENSOR_VAL_4B;
    sprintf(tBat, "%.6f", (double)data->battery);//[tin aws work]

    if (data->FOTAStat == (INT32)OTA_STAT_JOB_READY) {
        //updateOTAFlag = (INT32)OTA_STAT_JOB_READY;
        setOTAStat(OTA_STAT_JOB_READY);
    }

    // clear update flag in case of previouly being OTA confirmed status
    if (data->FOTAStat == (INT32)OTA_STAT_JOB_CONFIRMED) {
        //updateOTAFlag = (INT32)OTA_STAT_JOB_NONE;
        setOTAStat(OTA_STAT_JOB_NONE);
        memset(data->FOTAUrl, 0, sizeof(data->FOTAUrl));
        if (!pal_app_atc_work(data))
            aws_dpm_app_sensor_work(data);
    }

    if (strlen((char*)data->FOTAUrl) != 0) {
        sprintf((char*)aws_file_url, "%s", data->FOTAUrl);//[tin aws work]
    }

    if (data->doorOpenMode == 1) {
        doorOpenMode = 1;
    }

    IOT_INFO("current RTM user Timer ID = %d", data->tid)
    IOT_INFO("current RTM temperature(str): %s",
        data->temperature == INIT_SENSOR_VAL_4B ? SENSOR_VAL_NOT_AVAILABLE : tTemp)
    IOT_INFO("current RTM battery(str): %s", data->battery == INIT_SENSOR_VAL_4B ? SENSOR_VAL_NOT_AVAILABLE : tBat)
    IOT_INFO("current RTM doorOpen state: \"%s\"", data->doorOpen ? "true" : "false")
    IOT_INFO("current RTM doorOpenMode : %d", data->doorOpenMode)
    IOT_INFO("current RTM FOTAFlag: %d", data->FOTAStat)

    /* check printable code */
    if (data->FOTAUrl[0] > 0x7F) {
        IOT_INFO("current RTM FOTA url : \"???\"")
    } else {
        IOT_INFO("current RTM FOTA url : \"%s\"", data->FOTAUrl)
    }
}

static bool openControl(void)
{

    IOT_INFO("[openControl]\n")

    //ToDo::control a real doorlock here
    //
    doorOpenFlag = true;

    return true;
}

static bool closeControl(void)
{
    IOT_INFO("[closeControl]\n")

    //ToDo::control a real doorlock here
    //
    doorOpenFlag = false;

    return true;
}

static void controlDoorLock(app_dpm_info_rtm *_rtmData, INT32 _controlType, UINT8 _pubFlag)
{
    MQTTStatus_t rc = commonRC;
    BaseType_t xStatus = pdPASS;
    char pubTopics[MAX_SUBSCRIBE_TOPIC_LEN] = {0, };
    int flagToSend = 0;

    if (rc == MQTTSuccess) {
        memset(currentOpenMethod, 0, sizeof(currentOpenMethod));
        memset(pcPublishPayload, 0, sizeof(pcPublishPayload));
        memset(pubTopics, 0, sizeof(pubTopics));

        sprintf(pubTopics, "%s", getAWSCommandPubName());//[tin aws work]
    } else {
        LogError(("previous MQTT result(=%d) invalid", rc));
        return;
    }

    doorStateChange = 1;

    switch (_controlType) {
    case Door_Open: {
        if (openControl()) {
            sprintf(pcPublishPayload, "%s", AWS_RESPONSE_OPEN);//[tin aws work]
            sprintf(currentOpenMethod, "%s", AWS_RESPONSE_OPEN_APP);//[tin aws work]
            flagToSend = 1;
        }
    }
        break;
    case Door_Close: {
        if (closeControl()) {
            sprintf(pcPublishPayload, "%s", AWS_RESPONSE_CLOSE);//[tin aws work]
            sprintf(currentOpenMethod, "%s", AWS_RESPONSE_OPEN_APP);//[tin aws work]
            flagToSend = 1;
        }
    }
        break;
    case Door_Close_Timer: {
        if (closeControl()) {
            sprintf(pcPublishPayload, "%s", AWS_RESPONSE_CLOSE);//[tin aws work]
            sprintf(currentOpenMethod, "%s", AWS_RESPONSE_CLOSE_TIMER);//[tin aws work]
            flagToSend = 1;
        }
    }
        break;
    case Door_Open_MCU: {
        if (doorOpenFlag == true) {
            sprintf(pcPublishPayload, "%s", AWS_RESPONSE_OPEN);//[tin aws work]
        } else {
            sprintf(pcPublishPayload, "%s", AWS_RESPONSE_CLOSE);//[tin aws work]
        }
        sprintf(currentOpenMethod, "%s", AWS_RESPONSE_OPEN_MCU);//[tin aws work]
        flagToSend = 1;
    }
        break;
    case Door_Close_MCU: {
        sprintf(pcPublishPayload, "%s", AWS_RESPONSE_CLOSE);//[tin aws work]
        sprintf(currentOpenMethod, "%s", AWS_RESPONSE_OPEN_MCU);//[tin aws work]
        flagToSend = 1;
    }
        break;
    default: {
        LogError(("invalid operation"));
        sprintf(currentOpenMethod, "%s", AWS_RESPONSE_NOT_OPEN);//[tin aws work]
    }
        break;
    }

    if (_pubFlag == 0) {
        flagToSend = 0;
    }

    if (flagToSend) {
        xStatus = xPublishToTopic(&xMqttContext, pubTopics, (int32_t)strlen(pubTopics), pcPublishPayload,
            strlen(pcPublishPayload));
        if (xStatus != pdPASS) {
            LogError( ( "publish (command response) NG" ) );
            //ToDo::reconnection needed
            sprintf(currentOpenMethod, "%s", AWS_RESPONSE_NOT_OPEN);//[tin aws work]
            rc = MQTTSendFailed;
        } else {
            LogInfo(("publish (command response) OK -  payload: \"%s\"", pcPublishPayload));
        }
    }

    commonRC = rc;
}

static void connectionReadyInform(app_dpm_info_rtm *_rtmData)
{
    MQTTStatus_t rc = commonRC;
    BaseType_t xStatus = pdPASS;
    char pubTopics[MAX_SUBSCRIBE_TOPIC_LEN] = {0, };

    if (rc == MQTTSuccess) {
        memset(currentOpenMethod, 0, sizeof(currentOpenMethod));
        memset(pcPublishPayload, 0, sizeof(pcPublishPayload));
        memset(pubTopics, 0, sizeof(pubTopics));

        sprintf(pubTopics, "%s", getAWSCheckPubName());//[tin aws work]
        sprintf(currentOpenMethod, "%s", AWS_RESPONSE_NOT_OPEN);//[tin aws work]
    } else {
        LogError(("previous MQTT result(=%d) invalid", rc));
        return;
    }
    sprintf(pcPublishPayload, "%s", AWS_RESPONSE_CONNECT);//[tin aws work]
    //da16x_sprintf(pcPublishPayload, "%s", AWS_RESPONSE_CONNECT);

    xStatus = xPublishToTopic(&xMqttContext, pubTopics, (int32_t)strlen(pubTopics), pcPublishPayload, strlen(pcPublishPayload));
    if (xStatus != pdPASS) {
        LogError( ( "publish (command response) NG" ) );
        //ToDo::reconnection needed
        rc = MQTTSendFailed;
    } else {
        LogInfo(("publish (command response) OK -  payload: \"%s\"", pcPublishPayload));
    }

    commonRC = rc;
}

static void sensorUpdate(app_dpm_info_rtm *_rtmData)
{
    MQTTStatus_t rc = commonRC;
    BaseType_t xStatus = pdPASS;
    char pubTopics[MAX_SUBSCRIBE_TOPIC_LEN] = {0, };

    if (rc == MQTTSuccess) {
        memset(currentOpenMethod, 0, sizeof(currentOpenMethod));
        memset(pcPublishPayload, 0, sizeof(pcPublishPayload));
        memset(pubTopics, 0, sizeof(pubTopics));

        sprintf(pubTopics, "%s", getAWSCommandPubName());//[tin aws work]
        sprintf(currentOpenMethod, "%s", AWS_RESPONSE_NOT_OPEN);//[tin aws work]
    } else {
        LogError(("previous MQTT result(=%d) invalid", rc));
        return;
    }
    sprintf(pcPublishPayload, "%s", AWS_RESPONSE_SENSOR_UPDATE);//[tin aws work]

    xStatus = xPublishToTopic(&xMqttContext, pubTopics, (int32_t)strlen(pubTopics), pcPublishPayload, strlen(pcPublishPayload));
    if (xStatus != pdPASS) {
        LogError( ( "publish (command response) NG" ) );
        //ToDo::reconnection needed
        rc = MQTTSendFailed;
    } else {
        LogInfo(("publish (command response) OK -  payload: \"%s\"", pcPublishPayload));
    }

    commonRC = rc;
}

static INT32 app_parse_ota_uri(unsigned char *uri, size_t len)
{
    unsigned char *p = NULL;
    unsigned char *q = NULL;

    p = uri;

    q = (unsigned char*)"http";
    while (len && *q && tolower(*p) == *q) {
        ++p;
        ++q;
        --len;
    }

    if (*q) {
        LogError(("invalid prefix(http)"));
        goto error;
    }

    if (len && (tolower(*p) == 's')) {
        ++p;
        --len;
    }

    q = (unsigned char*)"://";
    while (len && *q && tolower(*p) == *q) {
        ++p;
        ++q;
        --len;
    }

    if (*q) {
        LogError(("invalid uri"));
        goto error;
    }

    return 0;

    error: return -1;

}

static INT32 aws_dpm_app_is_connected(void)
{
    char result_str[128] = {0, };
    char tmpStr[16] = {0, };
    char *ipaddrstr = NULL;
    int32_t len = 0;
    int32_t wait = 0;
    int32_t interval = 0;
    int32_t ping_interface = 0; /* default wlan0 */
    int32_t transmitted, reply_count;
    uint32_t ipaddr = 0;
    uint32_t count = 0;
    uint32_t average, time_min, ping_max;

    // result string
    transmitted = reply_count = 0;
    average = time_min = ping_max = 0;

    ipaddrstr = app_get_peer_ip_str();

    if (isvalidip(ipaddrstr)) {
        //ipaddr = (uint32_t)iptolong(ipaddrstr);//[tin aws work], must be replaced iptolong !!
        memcpy(tmpStr, ipaddrstr, strlen(ipaddrstr));
    } else {
        //ipaddr = (uint32_t)iptolong(DEFAULT_AWS_DNS_ADDR);//[tin aws work], must be replaced iptolong !!
        memcpy(tmpStr, DEFAULT_AWS_DNS_ADDR, strlen(DEFAULT_AWS_DNS_ADDR));
    }

    count = 4;		   // only 2
    len = 32;		   //default
    wait = 1200;	  // default 4sec (4000)
    interval = 500;  // interval default 1sec (1000)

    /* If station interface */
    ping_interface = 0; 				   //WLAN0_IFACE;

    app_print_elapse_time_ms("[%s:%d] Ping start (ipaddr=\"%s\")", __func__, __LINE__, tmpStr);
    /* ping client api execution with nodisplay as 1 and getting the string of result */
    rrq61x_ping_client(ping_interface, NULL, ipaddr, NULL, NULL, len, count, wait, interval, 1, result_str);//[tin aws work]

    /* parsing the result string */
    sscanf(result_str, "%lu,%lu,%lu,%lu,%lu", &transmitted, &reply_count, &average, &time_min, &ping_max);

    app_print_elapse_time_ms("[%s:%d] Ping end (reply count=%d)", __func__, __LINE__, reply_count);
    if (reply_count > 0) /* Success */
    {
        APRINTF("Ping reply is ok\n");
        commonRC = MQTTSuccess;
        return 1;
    }

    APRINTF("Ping reply is fail\n");

    commonRC = MQTTRecvFailed;
    return 0;
}

#define USE_SHADOW_ONLY_ON_SLEEP_1_N_2  1   //define whether subscribe only shadow or not
#define DEFAULT_SUBS_CNT_SHADOW_ONLY    2   // 2 shadows only
#define DEFAULT_SUBS_CNT                4   //command, OTA, and 2 shadows
static INT32 aws_dpm_app_subscription(void)
{
    BaseType_t xStatus = pdPASS;
    char subsTopics[MAX_SUBSCRIBE_TOPIC_LEN] = {0, };
    char regThingName[MAX_THING_NAME_LENGTH] = {0, };
    size_t lenRegThingName = 0;
    uint8_t cntTotalSubs = 0;
    uint8_t cntOKSubs = 0;
    uint8_t cntReservedSubs = DEFAULT_SUBS_CNT;

#if (USE_SHADOW_ONLY_ON_SLEEP_1_N_2 == 1)
    if (getSleepMode() != SLEEP_MODE_3) {
        cntReservedSubs = DEFAULT_SUBS_CNT_SHADOW_ONLY;
    }
#endif

    memset(regThingName, 0, sizeof(regThingName));
    strcpy(regThingName, app_get_registered_thing_name());

    lenRegThingName = strlen(regThingName);

    if (lenRegThingName == 0) {
        LogError(("registered thing name invalid!!!"));
        xStatus = pdFAIL;
        //ToDo::exception process
    }

    app_print_elapse_time_ms("[%s:%d] subscribing...", __func__, __LINE__);
    if (getSleepMode() == SLEEP_MODE_1 || getSleepMode() == SLEEP_MODE_2) {
#if (USE_SHADOW_ONLY_ON_SLEEP_1_N_2 == 1)
        LogInfo(("bypass subs for commmand and OTA due to sleep mode(=%d)", getSleepMode()));
        goto SUBS_SHADOW_ONLY;
#endif
    }
    /*
     * subscription path
     */
    //== command topic ==
    if (xStatus == pdPASS) {
        cntTotalSubs++;
        if ((xStatus = pal_app_reg_subscription_topic()) > 0) {
            if (xStatus == 1)
                xStatus = pdPASS;
            else
                xStatus = pdFAIL;
        } else {
            xStatus = xSubscribeToTopic(&xMqttContext, getAWSCommandSubName(), (uint16_t)strlen(getAWSCommandSubName()));
        }
        if (xStatus != pdPASS) {
            LogError(("subscription for command: NG"));
        } else {
            cntOKSubs++;
        }
    }

    //== job topc for OTA ==
    if (xStatus == pdPASS) {
        cntTotalSubs++;
        memset(subsTopics, 0, sizeof(subsTopics));
        sprintf(subsTopics, "%s%s%s%s", JOBS_API_PREFIX, regThingName, JOBS_API_BRIDGE,
        JOBS_API_NEXTJOBCHANGED);//[tin aws work]
        xStatus = xSubscribeToTopic(&xMqttContext, subsTopics, (uint16_t)strlen(subsTopics));
        if (xStatus != pdPASS) {
            LogError(("subscription for OTA job: NG"));
        } else {
            cntOKSubs++;
        }
    }

#if (USE_SHADOW_ONLY_ON_SLEEP_1_N_2 == 1)
    SUBS_SHADOW_ONLY:
#endif
    //== shadow topic ==
    /* for delta(desired) */
    /*
     if( xStatus == pdPASS )
     {
     cntTotalSubs++;
     memset(subsTopics, 0, sizeof(subsTopics));
     if (sizeof(DEFAULT_SHADOW_NAME) > 1)
     {
     da16x_sprintf(subsTopics, "%s%s%s%s%s%s", SHADOW_PREFIX, regThingName, SHADOW_NAMED_ROOT, DEFAULT_SHADOW_NAME, SHADOW_OP_UPDATE, SHADOW_SUFFIX_DELTA);
     }
     else //classic
     {
     da16x_sprintf(subsTopics, "%s%s%s%s%s", SHADOW_PREFIX, regThingName, SHADOW_CLASSIC_ROOT, SHADOW_OP_UPDATE, SHADOW_SUFFIX_DELTA);
     }
     xStatus = xSubscribeToTopic( &xMqttContext,
     subsTopics,
     SHADOW_TOPIC_LEN_UPDATE_DELTA( lenRegThingName, lenRegThingName ) );
     if (xStatus != pdPASS)
     {
     LogError(("subscription for shadow update delta: NG"));
     }
     else
     {
     cntOKSubs++;
     }
     }
     */
    /* for accepting shadow update */
    if (xStatus == pdPASS) {
        cntTotalSubs++;
        memset(subsTopics, 0, sizeof(subsTopics));
        if (sizeof(DEFAULT_SHADOW_NAME) > 1) {
            sprintf(subsTopics, "%s%s%s%s%s%s", SHADOW_PREFIX, regThingName,
            SHADOW_NAMED_ROOT, DEFAULT_SHADOW_NAME, SHADOW_OP_UPDATE, SHADOW_SUFFIX_ACCEPTED);//[tin aws work]
        } else //classic
        {
            sprintf(subsTopics, "%s%s%s%s%s", SHADOW_PREFIX, regThingName,
            SHADOW_CLASSIC_ROOT, SHADOW_OP_UPDATE, SHADOW_SUFFIX_ACCEPTED);//[tin aws work]
        }
        xStatus = xSubscribeToTopic(&xMqttContext, subsTopics,
            SHADOW_TOPIC_LEN_UPDATE_ACC(lenRegThingName, lenRegThingName));
        if (xStatus != pdPASS) {
            LogError(("subscription for shadow update accept: NG"));
        } else {
            cntOKSubs++;
        }
    }

    /* for rejecting shadow update */
    if (xStatus == pdPASS) {
        cntTotalSubs++;
        memset(subsTopics, 0, sizeof(subsTopics));
        if (sizeof(DEFAULT_SHADOW_NAME) > 1) {
            sprintf(subsTopics, "%s%s%s%s%s%s", SHADOW_PREFIX, regThingName,
            SHADOW_NAMED_ROOT, DEFAULT_SHADOW_NAME, SHADOW_OP_UPDATE, SHADOW_SUFFIX_REJECTED);//[tin aws work]
        } else //classic
        {
            sprintf(subsTopics, "%s%s%s%s%s", SHADOW_PREFIX, regThingName,
            SHADOW_CLASSIC_ROOT, SHADOW_OP_UPDATE, SHADOW_SUFFIX_REJECTED);//[tin aws work]
        }
        xStatus = xSubscribeToTopic(&xMqttContext, subsTopics,
            SHADOW_TOPIC_LEN_UPDATE_REJ(lenRegThingName, lenRegThingName));
        if (xStatus != pdPASS) {
            LogError(("subscription for shadow update reject: NG"));
        } else {
            cntOKSubs++;
        }
    }

    if (dpm_mode_is_wakeup() && !app_is_reconnected()) {
        app_dpm_set_rcv_ready();
    }

    if (app_is_persistent_session()) //checking persistent session
    {
        LogInfo(("bypass the duplicated subscribing to server due to %s", dpm_mode_is_wakeup() ? "DPM saved session" : "persistent session"));
        app_print_elapse_time_ms("[%s:%d] bypass the duplicated subscribing to server due to %s", __func__, __LINE__,
        dpm_mode_is_wakeup() ? "DPM saved session" : "persistent session");
    }

    if (cntTotalSubs >= cntReservedSubs && cntTotalSubs == cntOKSubs) {
        app_print_elapse_time_ms("[%s:%d] subscription : OK", __func__, __LINE__);
        LogInfo(("subscription info: total(default:%d, tried:%d), OK(%d)", cntReservedSubs, cntTotalSubs, cntOKSubs));
        return 0;
    } else {
        app_print_elapse_time_ms("[%s:%d] subscription : NG", __func__, __LINE__);
        LogError(("subscription info: total(default:%d, tried:%d), OK(%d)", cntReservedSubs, cntTotalSubs, cntOKSubs));
        return -1;
    }
}

static void aws_dpm_app_door_work(app_dpm_info_rtm *_rtmData)
{
    MQTTStatus_t rc = commonRC;
    app_dpm_info_rtm *data = (app_dpm_info_rtm*)_rtmData;

    BaseType_t xStatus = pdPASS;
    char shadowTopics[MAX_SUBSCRIBE_TOPIC_LEN] = {0, };
    char regThingName[MAX_THING_NAME_LENGTH] = {0, };
    size_t lenRegThingName = 0;

    RE_CHECK_AFTER_CONNECTION: memset(regThingName, 0, sizeof(regThingName));
    strcpy(regThingName, app_get_registered_thing_name());

    lenRegThingName = strlen(regThingName);

    if (lenRegThingName == 0) {
        LogError(("registered thing name invalid!!!"));
        xStatus = pdFAIL;
        //ToDo::exception process
    }

    if (rc != MQTTSuccess || doorLock != Door_Idle) {
        IOT_DEBUG("previous MQTT result = %d, doorLock CMD (=%d: 0-idle, 1-open, 2-close,"
            " 3-auto close)", rc, doorLock)
    }
    IOT_INFO("\n======================================================================="
        "================\n")
    //report shadow for doorlock related items
    if (rc != MQTTSuccess) {
        xStatus = pdFAIL;
    }

    if (xStatus == pdPASS) {
        memset(shadowTopics, 0, sizeof(shadowTopics));
        memset(pcPublishPayload, 0x00, sizeof(pcPublishPayload));

        if (sizeof(DEFAULT_SHADOW_NAME) > 1) {
            sprintf(shadowTopics, "%s%s%s%s%s%s", SHADOW_PREFIX, regThingName,
            SHADOW_NAMED_ROOT, DEFAULT_SHADOW_NAME, SHADOW_OP_UPDATE, "");//[tin aws work]
        } else //classic
        {
            sprintf(shadowTopics, "%s%s%s%s%s", SHADOW_PREFIX, regThingName,
            SHADOW_CLASSIC_ROOT, SHADOW_OP_UPDATE, "");//[tin aws work]
        }

        //defense against null string
        if (strlen(currentOpenMethod) < 1) {
            memset(currentOpenMethod, 0, sizeof(currentOpenMethod));
            sprintf(currentOpenMethod, "%s", AWS_RESPONSE_NOT_OPEN);//[tin aws work]
        }

        sprintf(pcPublishPayload,
        SHADOW_REPORTED_DOORLOCK_JSON, doorOpenFlag ? "true" : "false", currentOpenMethod, doorStateChange,
            doorOpenMode, getOTAStat(), currentOTAResult);//[tin aws work]

        xStatus = xPublishToTopic(&xMqttContext, shadowTopics,
            SHADOW_TOPIC_LEN_UPDATE(lenRegThingName, SHADOW_NAME_LENGTH), pcPublishPayload, strlen(pcPublishPayload));
        if (xStatus != pdPASS) {
            LogError( ( "publish (shadow doorlock update) NG" ) );
            //ToDo::reconnection needed
            rc = MQTTSendFailed;
        } else {
            LogInfo(("publish (shadow doorlock update) OK -	payload: \"%s\"", pcPublishPayload));
        }
    }

    IOT_INFO("*************************************************************************"
        "****************\n")

    if (data && xStatus == pdPASS) {
        data->doorOpen = (bool)doorOpenFlag;
        data->FOTAStat = (INT32)getOTAStat();
        if (getOTAStat() == (INT32)OTA_STAT_JOB_READY && strlen((char*)aws_file_url) > 0) {
            sprintf((char*)data->FOTAUrl, "%s", aws_file_url);//[tin aws work]
        } else if (getOTAStat() == (INT32)OTA_STAT_JOB_CONFIRMED && strlen((char*)aws_file_url) > 0) {
            memset(data->FOTAUrl, 0, sizeof(data->FOTAUrl));
        }

        IOT_INFO("last user Timer ID = %d", data->tid)
        IOT_INFO("last doorOpenFlag state: \"%s\"", data->doorOpen ? "true" : "false")
        IOT_INFO("last FOTA Stat: %d", getOTAStat())
        /* check printable code */
        if (aws_file_url[0] > 0x7F) {
            IOT_INFO("last FOTA Url: \"???\"")
        } else {
            IOT_INFO("last FOTA Url: \"%s\"", aws_file_url)
        }
    }

    doorStateChange = 0;

    if (rc != MQTTSuccess) {
        IOT_INFO("[%s] reconnecting...", __func__)
        aws_dpm_app_connect(data);
        rc = commonRC;
        goto RE_CHECK_AFTER_CONNECTION;
    }

}

static void aws_dpm_app_sensor_work(app_dpm_info_rtm *_rtmData)
{
    MQTTStatus_t rc = commonRC;
    BaseType_t xStatus = pdPASS;
    char shadowTopics[MAX_SUBSCRIBE_TOPIC_LEN] = {0, };
    char regThingName[MAX_THING_NAME_LENGTH] = {0, };
    size_t lenRegThingName = 0;
    char tTemp[MAX_RTM_FLOAT_STRING] = {0, };
    char tBat[MAX_RTM_FLOAT_STRING] = {0, };

    app_dpm_info_rtm *data = (app_dpm_info_rtm*)_rtmData;

    RE_CHECK_AFTER_CONNECTION: memset(regThingName, 0, sizeof(regThingName));
    strcpy(regThingName, app_get_registered_thing_name());

    lenRegThingName = strlen(regThingName);

    if (lenRegThingName == 0) {
        LogError(("registered thing name invalid!!!"));
        xStatus = pdFAIL;
        //ToDo::exception process
    }

    if (rc != MQTTSuccess || doorLock != Door_Idle) {
        IOT_DEBUG("previous MQTT rc = %d, doorLock CMD (=%d: 0-idle, 1-open, 2-close,"
            " 3-auto close)", rc, doorLock)
    }

    IOT_DEBUG("read values from sensor if available")

    currentTemperature = (float)INIT_SENSOR_VAL_4B;
    currentBattery = (float)INIT_SENSOR_VAL_4B;

    IOT_INFO("\n======================================================================="
        "================\n")
    //if(currentTemperature > 0)
    {
        sprintf(tTemp, "%.6f", (double)currentTemperature);//[tin aws work]
    }

    //if(currentBattery > 0)
    {
        sprintf(tBat, "%.6f", (double)currentBattery);//[tin aws work]
    }

    //report shadow for sensor related items
    if (rc != MQTTSuccess) {
        xStatus = pdFAIL;
    }

    if (xStatus == pdPASS) {
        memset(shadowTopics, 0, sizeof(shadowTopics));
        memset(pcPublishPayload, 0x00, sizeof(pcPublishPayload));

        if (sizeof(DEFAULT_SHADOW_NAME) > 1) {
            sprintf(shadowTopics, "%s%s%s%s%s%s", SHADOW_PREFIX, regThingName,
            SHADOW_NAMED_ROOT, DEFAULT_SHADOW_NAME, SHADOW_OP_UPDATE, "");//[tin aws work]
        } else //classic
        {
            sprintf(shadowTopics, "%s%s%s%s%s", SHADOW_PREFIX, regThingName,
            SHADOW_CLASSIC_ROOT, SHADOW_OP_UPDATE, "");//[tin aws work]
        }

        sprintf(pcPublishPayload,
        SHADOW_REPORTED_SENSOR_JSON, doorOpenFlag ? "true" : "false", (double)currentTemperature, (double)currentBattery);

        xStatus = xPublishToTopic(&xMqttContext, shadowTopics,
            SHADOW_TOPIC_LEN_UPDATE(lenRegThingName, SHADOW_NAME_LENGTH), pcPublishPayload, strlen(pcPublishPayload));
        if (xStatus != pdPASS) {
            LogError( ( "publish (shadow sensor update) NG" ) );
            //ToDo::reconnection needed
            rc = MQTTSendFailed;
        } else {
            LogInfo(("publish (shadow sensor update) OK -	payload: \"%s\"", pcPublishPayload));
        }
    }

    IOT_INFO("*************************************************************************"
        "**************\n")

    if (data) {
        data->temperature = (float)currentTemperature;
        data->battery = (float)currentBattery;
        IOT_INFO("last temperature: %s", data->temperature == INIT_SENSOR_VAL_4B ? SENSOR_VAL_NOT_AVAILABLE : tTemp)
        IOT_INFO("last battery: %s", data->battery == INIT_SENSOR_VAL_4B ? SENSOR_VAL_NOT_AVAILABLE : tBat)
    }

    if (rc != MQTTSuccess) {
        IOT_INFO("[%s] reconnecting...(rc=%d)", __func__, rc)
        aws_dpm_app_connect(_rtmData);
        rc = commonRC;
        goto RE_CHECK_AFTER_CONNECTION;
    }

}

static void aws_dpm_app_init(void)
{
    INT32 rcode;

    //add OTA result check
    memset(currentOTAResult, 0, sizeof(currentOTAResult));
    if (api_usr_nvram_read_int(AWS_NVRAM_CONFIG_OTA_RESULT, (int32_t *)&rcode)) {
        sprintf(currentOTAResult, "%s", AWS_UPDATE_OTA_UNKNOWN);//[tin aws work]
        LogInfo(("read AWS_NVRAM_CONFIG_OTA_RESULT init status"));
    } else {
        if (rcode == AWS_OTA_RESULT_OK) {
            sprintf(currentOTAResult, "%s", AWS_UPDATE_OTA_OK);//[tin aws work]
            api_usr_nvram_delete_item(AWS_NVRAM_CONFIG_OTA_URL);
            if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_STATE, AWS_OTA_STATE_UNKOWN)) {
                LogError(("write AWS_NVRAM_CONFIG_OTA_STATE failed"));
            } LogInfo(("AWS_UPDATE_OTA_OK "));
        } else if (rcode == AWS_OTA_RESULT_NG) {
            char *tmp_url = NULL;
            sprintf(currentOTAResult, "%s", AWS_UPDATE_OTA_NG);//[tin aws work]
            tmp_url = api_usr_nvram_read_string(AWS_NVRAM_CONFIG_OTA_URL);//[tin aws work]
            if (tmp_url) {
                memset(aws_file_url, 0, sizeof(aws_file_url));
                if (app_parse_ota_uri((unsigned char*)tmp_url, strlen(tmp_url)) == 0) {
                    strncpy((char*)aws_file_url, (const char*)tmp_url, strlen(tmp_url));
                    //for retry when failed
                    if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_STATE, AWS_OTA_STATE_READY)) {
                        LogError(("write AWS_NVRAM_CONFIG_OTA_STATE for retry failed"));
                    }
                } else {
                    api_usr_nvram_delete_item(AWS_NVRAM_CONFIG_OTA_URL);
                    api_usr_nvram_delete_item(AWS_NVRAM_CONFIG_OTA_STATE);
                }
            }LogInfo(("AWS_UPDATE_OTA_NG"));
        } else {
            sprintf(currentOTAResult, "%s", AWS_UPDATE_OTA_UNKNOWN);//[tin aws work]
            //delete_nvram_env(AWS_NVRAM_CONFIG_OTA_STATE);
            LogInfo(("AWS_UPDATE_OTA_UNKNOWN"));
        }
    }

    if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_RESULT, AWS_OTA_RESULT_UNKNOWN)) {
        LogError(("write AWS_NVRAM_CONFIG_OTA_RESULT failed"));
    }

    //add OTA status check
    if (api_usr_nvram_read_int(AWS_NVRAM_CONFIG_OTA_STATE, (int32_t *)&rcode)) {
        setOTAStat(OTA_STAT_JOB_NONE);
        LogInfo(("read AWS_NVRAM_CONFIG_OTA_STATE init status"));
    } else {
        if (rcode == AWS_OTA_STATE_READY) {
            setOTAStat(OTA_STAT_JOB_READY);
            LogInfo(("OTA_STAT_JOB_READY"));
        } else {
            setOTAStat(OTA_STAT_JOB_NONE);
            LogInfo(("OTA_STAT_JOB_NONE"));
        }
    }
}

static void aws_dpm_app_connect(app_dpm_info_rtm *_rtmData)
{
    BaseType_t xStatus = pdPASS;
    static UINT8 fail_count = 0;

    LogInfo( ( "Establishing MQTT session with provisioned certificate..." ) );

    RETRY_CONNECTION: if (xAppConnectionEstablished == true) {
        LogInfo( ( "Disconnecting MQTT session for reconnection..." ) );
//[[PCKS11 used or not
        if (getUseFPstatus()) {
            xDisconnectMqttSession(&xMqttContext, &xNetworkContext);
        } else {
            xDisconnectMqttSession(&xMqttContext, &xNetworkContext);
        }
//]]
        xAppConnectionEstablished = false;
    }

    /* Set the pParams member of the network context with desired transport. */
    xNetworkContext.pxParams = &xTlsTransportParams;

//[[PCKS11 used or not
    if (getUseFPstatus()) {
        xStatus = xEstablishMqttSession_P11(&xMqttContext, &xNetworkContext, &xBuffer, prvEventCallback,
        pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
        pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS);
    } else {
        xStatus = xEstablishMqttSession(&xMqttContext, &xNetworkContext, &xBuffer, prvEventCallback);
    }
//]]
    if (xStatus != true) {
        LogError( ( "Failed to establish MQTT session with provisioned "
                "credentials. Verify on your AWS account that the "
                "new certificate is active and has an attached IoT "
                "Policy that allows the \"iot:Connect\" action." ) );
        //ToDo::exception process when infinite connection failure happened
        if (getUseFPstatus()) {
            //xDisconnectMqttSession_P11(&xMqttContext, &xNetworkContext);//[tin aws work], org
            xDisconnectMqttSession(&xMqttContext, &xNetworkContext);
        } else {
            //xEstablishMqttSession(&xMqttContext, &xNetworkContext, &xBuffer, prvEventCallback);//[tin aws work], org
            xDisconnectMqttSession(&xMqttContext, &xNetworkContext);
        }
        xAppConnectionEstablished = false;
        fail_count++;
        if (fail_count > MAX_RETRY_CNT_TO_SLEEP) {
            goSleepAppOnException(fail_count);
        }
    } else {
        LogInfo( ( "Sucessfully established connection with provisioned credentials." ) );
        xAppConnectionEstablished = true;
        fail_count = 0;
    }

    if (xAppConnectionEstablished) {
        if (aws_dpm_app_subscription()) {
            goto RETRY_CONNECTION;
        } else {
            if (dpm_mode_is_enabled() && !app_is_reconnected()) {
                checkCurrentDeviceStatus(_rtmData);
            }
        }
    }

    commonRC = MQTTSuccess;

}

static void aws_dpm_app_recv(app_dpm_info_rtm *_rtmData)
{
    MQTTStatus_t rc = commonRC;

    if (rc != MQTTSuccess || doorLock != Door_Idle) {
        IOT_DEBUG("previous MQTT result = %d, doorLock CMD (=%d: 0-idle, 1-open, 2-close,"
            " 3-auto close)", rc, doorLock)
    }

    while (1) {
        app_print_elapse_time_ms("[%s:%d] recv loop timeout = %d", __func__, __LINE__,
        UC_WAKEUP_RECV_TIMEOUT);
        //rc = MQTT_ProcessLoop(&xMqttContext, UC_WAKEUP_RECV_TIMEOUT);//[tin aws work]
        rc = MQTT_ProcessLoop(&xMqttContext);//[tin aws work]

        if (rc != MQTTSuccess) {
            LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                    MQTT_Status_strerror( rc ) ) );
            IOT_INFO("[%s] reconnecting...(reason=%d)", __func__, rc)
            OAL_MSLEEP(100);
            aws_dpm_app_connect(_rtmData);
            continue;
        }

        if (getOTAStat() < OTA_STAT_JOB_CONFIRMED) {
            if (controlFlag == true) {
                if (pal_app_controlCommand(_rtmData)) {
                    pal_app_atc_work(_rtmData);
                } else {
                    controlDoorLock(_rtmData, doorLock, 1);
                    aws_dpm_app_door_work(_rtmData);
                    doorLock = Door_Idle;
                }
            }
            if (connectFlag == true) {
                connectionReadyInform(_rtmData);
                pal_app_atc_work(_rtmData);
            }

            if (updateSensorFlag == true) {
                if (!pal_app_atc_work(_rtmData)) {
                    sensorUpdate(_rtmData);
                    aws_dpm_app_sensor_work(_rtmData);
                }
            }

            if (controlFlag != true && connectFlag != true && updateSensorFlag != true
                && (getOTAStat() == OTA_STAT_JOB_READY)) {
                if (!pal_app_atc_work(_rtmData)) {
                    aws_dpm_app_door_work(_rtmData);
                }
            }

            if (controlFlag == true || connectFlag == true || updateSensorFlag == true) {
                controlFlag = false;
                connectFlag = false;
                updateSensorFlag = false;
            }
        } else {
            //Max time the yield function will wait for read messages
            //rc = MQTT_ProcessLoop(&xMqttContext, UC_WAKEUP_RECV_TIMEOUT * 5);
            rc = MQTT_ProcessLoop(&xMqttContext);//[tin aws work]

            if (rc != MQTTSuccess) {
                LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                        MQTT_Status_strerror( rc ) ) );
            }
            commonRC = rc;
            if (!pal_app_atc_work(_rtmData))
                aws_dpm_app_door_work(_rtmData);

#if defined(__SUPPORT_OTA__)
            INT32 flag = 1;
            INT32 rcode = 0;
            IOT_INFO("URL for updating: \"%s\"", aws_file_url)
            IOT_INFO("save URL info & reboot for OTA")
            OAL_MSLEEP(30);
            rcode = api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_FLAG, flag);
            OAL_MSLEEP(30);
            if (rcode) {
                IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_FLAG failed => force to sleep");
                OAL_MSLEEP(30);
                goto FORCED_END;
            }

            reboot_func(SYS_REBOOT_POR);

            /* Wait for system-reboot */
            while (1) {
                OAL_MSLEEP(100);
            }
#endif // (__SUPPORT_OTA__)
        }

        goto FORCED_END;
    }

    FORCED_END:

    return;
}

static void aws_dpm_app_boot(app_dpm_info_rtm *_rtmData, DM_NOTI _status)
{
    //report connection
    if (getSleepMode() == SLEEP_MODE_3) {
        //report connection status
        connectionReadyInform(_rtmData);
        //doorlock set default state to close
        controlDoorLock(_rtmData, Door_Close, 0);
    }
    //report doorlock shadow
    if (!pal_app_atc_work(_rtmData))
        aws_dpm_app_door_work(_rtmData);
}

static void aws_dpm_app_finish_loop(app_dpm_info_rtm *_rtmData)
{
    MQTTStatus_t rc = MQTTSuccess;
    static UINT8 exception_count = 0;

    CHECK_SLEEP: rc = commonRC;
    if (rc == MQTTSuccess && !app_dpm_get_send_pub_flag() && !app_dpm_get_wait_job_next_flag()) {
        if (dpm_mode_is_enabled()) {
            if (app_dpm_get_recv_timeout_flag() == DPM_RCV_OK_CONNECT) {
                app_dpm_set_recv_timeout_flag(DPM_RCV_OK_SLEEP);
            }
        }
    } else {
        INT32 loopCnt = 0;
        UINT8 flag_pub;
        UINT8 flag_job_next;

        //1st: recv count scenario
        do {
            loopCnt++;
            //rc = MQTT_ProcessLoop(&xMqttContext, UC_WAKEUP_RECV_TIMEOUT); // 200ms
            rc = MQTT_ProcessLoop(&xMqttContext); // 200ms//[tin aws work]
            app_print_elapse_time_ms("[%s:%d] commonRC = %d, send_pub_flag()=%d, wait_job_flag()=%d", __func__,
            __LINE__, rc, app_dpm_get_send_pub_flag(), app_dpm_get_wait_job_next_flag());
            if (rc != MQTTSuccess || loopCnt > MAX_PUB_ACK_OR_JOB_WAIT_CNT) // 1000ms
            {
                break;
            }
        } while (app_dpm_get_send_pub_flag() || app_dpm_get_wait_job_next_flag());

        //2nd: Ping scenario
        flag_pub = app_dpm_get_send_pub_flag();
        flag_job_next = app_dpm_get_wait_job_next_flag();
        if (flag_pub || flag_job_next) {
            LogInfo(("Ping to server due to PUB ACK(%d) or Next Job notify(%d) not received from server", flag_pub, flag_job_next));
            if (!aws_dpm_app_is_connected()) {
                aws_dpm_app_connect(_rtmData);
                exception_count = 0;
            } else {
                if (exception_count++ > MAX_RETRY_CNT_TO_SLEEP) {
                    goSleepAppOnException(exception_count);
                }
            }
        }
        goto CHECK_SLEEP;
    }

    while (1) {
        app_print_elapse_time_ms("[%s:%d] recv loop timeout = %d", __func__, __LINE__,
        FINISH_LOOP_RECV_TIMEOUT);
        vTaskDelay(1);
        //rc = MQTT_ProcessLoop(&xMqttContext, FINISH_LOOP_RECV_TIMEOUT); // 50ms
        rc = MQTT_ProcessLoop(&xMqttContext); // 50ms//[tin aws work]

        if (rc != MQTTSuccess) {
            LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                    MQTT_Status_strerror( rc ) ) );
            IOT_INFO("[%s] reconnecting...(reason=%d)", __func__, rc)
            OAL_MSLEEP(100);
            aws_dpm_app_connect(_rtmData);
            continue;
        }
    }
}

static void aws_nodpm_app_work(app_dpm_info_rtm *_rtmData)
{
    INT32 dbgCnt = 0;

    while (1) {
        dbgCnt++;

        aws_dpm_app_recv(_rtmData);

        if (dbgCnt % 100 == 0) {
            IOT_DEBUG("status rcode=%d", commonRC)
        }

        OAL_MSLEEP(500);
    }

}

void DPM_App_Main(UINT32 _data, UINT32 _rtmData, DM_NOTI _status)
{
    app_dpm_info_rtm *rtmData = (app_dpm_info_rtm*)_rtmData;

    switch (_status) {
    case DM_INIT: {
        app_print_elapse_time_ms("[%s:%d]", __func__, __LINE__);
        IOT_INFO("DM_INIT \n")

#if defined(__SUPPORT_ATCMD__WORK)//[tin aws work]
        pal_app_get_atcmd_parameter();
#endif
        if (getUseFPstatus()) {
            //check whether this device registered or not
            if (0/*app_is_needed_fleet_provisioning()*/ /*[tin aws work], build error fix it later*/) {
                LogInfo(("fleet provisioning start..."));
                app_provinsioning_device_service();
            } else {
                LogInfo(("this is the provisioned device (thing ID: %s) using certi from NVRAM", app_get_registered_thing_name()));
            }
        } else {
            app_set_registered_thing_name(getAPPThingName()); //pre-registered thing used
            LogInfo(("this is the pre-registered device (thing ID: %s) using certi from app_aws_certi.h", app_get_registered_thing_name()));
        }

        aws_dpm_app_init();
        pal_app_at_command_status(ATCMD_Status_STA_start);
    }
        break;
    case DM_NEED_CONNECTION: {
        app_print_elapse_time_ms("[%s:%d]", __func__, __LINE__);
        IOT_INFO("DM_NEED_CONNECTION \n")

        aws_dpm_app_connect(rtmData);
    }
        break;
    case DM_CHECK_RECV: {

    }
        break;
    case DM_WAKEUP_RECV: {
        app_print_elapse_time_ms("[%s:%d]", __func__, __LINE__);
        IOT_INFO("DM_WAKEUP_RECV \n")

        aws_dpm_app_recv(rtmData);
    }
        break;
    case DM_WAKEUP_SENSOR: {
        app_print_elapse_time_ms("[%s:%d]", __func__, __LINE__);
        IOT_INFO("DM_WAKEUP_SENSOR (or external wakeup) \n")

        if (!pal_app_atc_work(rtmData)) {
            // normal sensor update
            aws_dpm_app_sensor_work(rtmData);
        }
    }
        break;
    case DM_WAKEUP_TIMER:	// if opened, timer check for close
    {
        app_print_elapse_time_ms("[%s:%d]", __func__, __LINE__);
        IOT_INFO("DM_WAKEUP_TIMER (tid=%d) \n", rtmData->tid)

        if (!pal_app_atc_work(rtmData)) {
            // normal sensor update instead of ping send
            aws_dpm_app_sensor_work(rtmData);
        }
    }
        break;
    case DM_WAKEUP_BOOT: {
        app_print_elapse_time_ms("[%s:%d]", __func__, __LINE__);
        IOT_INFO("DM_WAKEUP_BOOT \n")

        aws_dpm_app_boot(rtmData, DM_WAKEUP_BOOT);
    }
        break;
    case DM_EXTERNAL_SENSOR: {

    }
        break;
    case DM_FINISH_DEVICE: {
        app_print_elapse_time_ms("[%s:%d]", __func__, __LINE__);
        IOT_INFO("DM_FINISH_DEVICE \n")
        pal_app_at_command_status(ATCMD_Status_STA_done);
        aws_dpm_app_finish_loop(rtmData);

    }
        break;

    case DM_NO_DPM_MODE: {
        IOT_INFO("DM_NO_DPM_MODE \n")

        aws_nodpm_app_work(rtmData);

    }
        break;

    case DM_CHECK_DEVICE: {
        IOT_INFO("DM_CHECK_DEVICE \n")

        /* check communication with the peer server */
        /* just sleep without resetting KA timer */
        goSleepAppDpmThread(0, DPM_RTC_NORMAL_MODE);

    }
        break;

    default: {
    }
        break;
    }

}

void aws_dpm_app_sample_thread(void)
{
    int sleepMode = 0;
    int rtcTime = 0;
    unsigned char useRTM = FALSE;
    INT32 rcode;
    INT32 flagOTA;
    char *tmp_url = NULL;
    UINT32 my_port = UNDEF_PORT;
    UINT32 uSizeStack = 0;

    dpmAPPDataQ sampleData;

    //check OTA
    rcode = api_usr_nvram_read_int(AWS_NVRAM_CONFIG_OTA_FLAG, (int32_t *)&flagOTA);//[tin aws work]
    if (!rcode && flagOTA == 1) {
        if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_RESULT, AWS_OTA_RESULT_NG)) {
            IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_RESULT failed\n");
        }
        vTaskDelay(1);
        tmp_url = api_usr_nvram_read_string(AWS_NVRAM_CONFIG_OTA_URL);//[tin aws work]
        if (tmp_url) {
            flagOTA = 0;
            if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_FLAG, flagOTA)) {
                IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_FLAG failed");
            }
            vTaskDelay(1);
            strncpy((char*)aws_file_url, (const char*)tmp_url, strlen(tmp_url));
#if defined(__SUPPORT_OTA__)			
            aws_ota_fw_update((char*)aws_file_url);
#endif
            return;
        } else {
            IOT_ERROR("OTA URL string invalid");
        }
    }

    api_usr_nvram_read_int((const char*)SLEEP_MODE_FOR_NARAM, (int32_t*)&sleepMode);//[tin aws work]
    api_usr_nvram_read_int((const char*)SLEEP_MODE2_RTC_TIME, (int32_t*)&rtcTime);//[tin aws work]

#if defined(__RUN_APP_SLEEP_2__)
    sleepMode = SLEEP_MODE_2;
#endif //__RUN_APP_SLEEP_2__

    //check validation
    if (sleepMode > SLEEP_MODE_3 || sleepMode <= SLEEP_MODE_NONE) {
        sleepMode = SLEEP_MODE_3; //default
        useRTM = TRUE;
    }

    if (rtcTime <= 0) {
        rtcTime = AWS_CONFIG_KEEP_INTERVAL_MAX;
        if (sleepMode == SLEEP_MODE_2) {
            rtcTime = (int)(getAppSleep2Interval(SLEEP_2_WAKEUP_TIME_INTERVAL_SEC) / 1000000);
        }
    }

    if (sleepMode == SLEEP_MODE_1) {
        if (SLEEP_1_USE_RTM != 0) {
            useRTM = TRUE;
        } else {
            useRTM = FALSE;
        }
    } else if (sleepMode == SLEEP_MODE_2) {
        if (SLEEP_2_USE_RTM != 0) {
            useRTM = TRUE;
        } else {
            useRTM = FALSE;
        }
    } else {
        useRTM = TRUE;
    }

    APRINTF("sleepMode: %d, rtcTime: %d \n\n", sleepMode, rtcTime);

    setSleepMode((APPSleepMode)sleepMode, rtcTime, useRTM);

    my_port = app_dpm_get_client_socket_port();
    if (my_port == UNDEF_PORT)
        pal_app_get_def_local_port((uint32_t*)&my_port);

    if (getUseFPstatus()) { //more stack needed
        uSizeStack = (1024 * 16) / sizeof(StackType_t);
    } else {
        uSizeStack = (1024 * 8) / sizeof(StackType_t);
    }

    dpmAppThreadCreate(APP_AWS_SHADOW, DPM_App_Main, (UINT32)NULL, sizeof(app_dpm_info_rtm), uSizeStack,
    AWS_SUBTASK_PRIORITY + 1, my_port, (UINT32)rtcTime, DEFAULT_AWS_DNS_ADDR,
    DEFAULT_AWS_2ND_DNS_ADDR, SNTP_TRY_COUNT);

    sendDPMAppMSGQ(&sampleData);

    return;
}

void aws_shadow_dpm_auto_start(void *arg)
{
    int sysmode;

#if defined (__BLE_COMBO_REF__) //added for combo::da16600work
    {
        int32_t status = pdPASS;
        int32_t cnt = 0;
        while (1)
        {
            if (check_net_init(WLAN0_IFACE) == pdPASS)
            {
                break;
            }
            vTaskDelay(50);
        }

        /* Waiting netif status */
        status = wifi_netif_status(WLAN0_IFACE);
        while (status == 0xFF || status != pdPASS || wifi_svc_get_provisioning_flag())
        {
            vTaskDelay(50);
            status = wifi_netif_status(WLAN0_IFACE);
            cnt++;
            if (cnt % 60 == 59)
            {
                APRINTF("wifi checking...(provision flag=%d)\n", wifi_svc_get_provisioning_flag());
            }
        }

        RTC_CLEAR_EXT_SIGNAL(); // clear wakeup source:: by Mike
    }
#endif // __BLE_COMBO_REF__    

    sysmode = 0; //getSysMode();//[tin aws work], build error 

    APRINTF_S("\n===========================================\n\n");
    pal_app_set_prov_feature();
    APRINTF("[ aws_shadow_dpm_auto_start]\n\n");
    if (sysmode == SYSMODE_STA_ONLY) {
        APRINTF("\nAWS_IOT on Station Mode for \"%s\" \n\n", getAPPThingName());
    }
    APRINTF_S("============================================\n\n");
    pal_app_dpm_auto_start();

    if (sysmode == SYSMODE_AP_ONLY || sysmode == SYSMODE_STA_N_AP) {
        APRINTF("\nAWS_IOT AP Mode  %s \n\n", getAPPThingName());

#if !defined (__BLE_COMBO_REF__) //da16600work::wifi provisioning not used
        if (getUseFPstatus()) {
            if (app_is_needed_fleet_provisioning()) {
                pal_app_start_provisioning(AWS_MODE_FPGEN);
            } else {
                //using certi from NVRAM
                pal_app_start_provisioning(AWS_MODE_GEN);
            }
        } else {
            //using certi from app_aws_certi.h
            pal_app_start_provisioning(AWS_MODE_GEN);
        }
#endif //!(__BLE_COMBO_REF__)

        vTaskDelete(NULL);
        return;
    }
    pal_app_check_ping();
    pal_app_at_command_status(ATCMD_Status_network_OK);
    aws_dpm_app_sample_thread();

    vTaskDelete(NULL);
}

// ( __USE_FLEET_PROVISION__ )
static bool prvSubscribeToCsrResponseTopics(void)
{
    bool xStatus = false;

    if (getUseFPstatus() == 0) {
        return xStatus;
    }

    xStatus = xSubscribeToTopic(&xMqttContext,
    FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC,
    FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH);

    if (xStatus == false) {
        LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH,
                FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC ) );
    }

    if (xStatus == true) {
        xStatus = xSubscribeToTopic(&xMqttContext,
        FP_CBOR_CREATE_CERT_REJECTED_TOPIC,
        FP_CBOR_CREATE_CERT_REJECTED_LENGTH);
        if (xStatus == false) {
            LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                    FP_CBOR_CREATE_CERT_REJECTED_LENGTH,
                    FP_CBOR_CREATE_CERT_REJECTED_TOPIC ) );
        }
    }

    return xStatus;
}

static bool prvUnsubscribeFromCsrResponseTopics(void)
{
    bool xStatus = false;

    if (getUseFPstatus() == 0) {
        return xStatus;
    }

    xStatus = xUnsubscribeFromTopic(&xMqttContext,
    FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC,
    FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH);

    if (xStatus == false) {
        LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH,
                FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC ) );
    }

    if (xStatus == true) {
        xStatus = xUnsubscribeFromTopic(&xMqttContext,
        FP_CBOR_CREATE_CERT_REJECTED_TOPIC,
        FP_CBOR_CREATE_CERT_REJECTED_LENGTH);

        if (xStatus == false) {
            LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                    FP_CBOR_CREATE_CERT_REJECTED_LENGTH,
                    FP_CBOR_CREATE_CERT_REJECTED_TOPIC ) );
        }
    }

    return xStatus;
}
static bool prvSubscribeToRegisterThingResponseTopics(void)
{
    bool xStatus = false;

    if (getUseFPstatus() == 0) {
        return xStatus;
    }

    xStatus = xSubscribeToTopic(&xMqttContext, FP_CBOR_REGISTER_ACCEPTED_TOPIC(PROVISIONING_TEMPLATE_NAME),
        FP_CBOR_REGISTER_ACCEPTED_LENGTH(PROVISIONING_TEMPLATE_NAME_LENGTH));

    if (xStatus == false) {
        LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
    }

    if (xStatus == true) {
        xStatus = xSubscribeToTopic(&xMqttContext, FP_CBOR_REGISTER_REJECTED_TOPIC(PROVISIONING_TEMPLATE_NAME),
            FP_CBOR_REGISTER_REJECTED_LENGTH(PROVISIONING_TEMPLATE_NAME_LENGTH));
        if (xStatus == false) {
            LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                    FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                    FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
        }
    }

    return xStatus;
}

static bool prvUnsubscribeFromRegisterThingResponseTopics(void)
{
    bool xStatus = false;

    if (getUseFPstatus() == 0) {
        return xStatus;
    }

    xStatus = xUnsubscribeFromTopic(&xMqttContext, FP_CBOR_REGISTER_ACCEPTED_TOPIC(PROVISIONING_TEMPLATE_NAME),
        FP_CBOR_REGISTER_ACCEPTED_LENGTH(PROVISIONING_TEMPLATE_NAME_LENGTH));

    if (xStatus == false) {
        LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
    }

    if (xStatus == true) {
        xStatus = xUnsubscribeFromTopic(&xMqttContext, FP_CBOR_REGISTER_REJECTED_TOPIC(PROVISIONING_TEMPLATE_NAME),
            FP_CBOR_REGISTER_REJECTED_LENGTH(PROVISIONING_TEMPLATE_NAME_LENGTH));

        if (xStatus == false) {
            LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                    FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                    FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
        }
    }

    return xStatus;
}

static void prvProvisioningPublishCallback(MQTTContext_t *pxMqttContext, MQTTPacketInfo_t *pxPacketInfo,
    MQTTDeserializedInfo_t *pxDeserializedInfo)
{
    if (getUseFPstatus()) {
        FleetProvisioningStatus_t xStatus;
        FleetProvisioningTopic_t xApi;
        MQTTPublishInfo_t *pxPublishInfo;

        configASSERT(pxMqttContext != NULL);
        configASSERT(pxPacketInfo != NULL);
        configASSERT(pxDeserializedInfo != NULL);

        /* Suppress the unused parameter warning when asserts are disabled in
         * build. */
        (void)pxMqttContext;

        /* Handle an incoming publish. The lower 4 bits of the publish packet
         * type is used for the dup, QoS, and retain flags. Hence masking
         * out the lower bits to check if the packet is publish. */
        if ((pxPacketInfo->type & 0xF0U) == MQTT_PACKET_TYPE_PUBLISH) {
            configASSERT(pxDeserializedInfo->pPublishInfo != NULL);
            pxPublishInfo = pxDeserializedInfo->pPublishInfo;

            xStatus = FleetProvisioning_MatchTopic(pxPublishInfo->pTopicName, pxPublishInfo->topicNameLength, &xApi);

            if (xStatus != FleetProvisioningSuccess) {
                LogWarn( ( "Unexpected publish message received. Topic: %.*s.",
                        ( int ) pxPublishInfo->topicNameLength,
                        ( const char * ) pxPublishInfo->pTopicName ) );
            } else {
                if (xApi == FleetProvCborCreateCertFromCsrAccepted) {
                    LogInfo( ( "Received accepted response from Fleet Provisioning CreateCertificateFromCsr API." ) );

                    xResponseStatus = ResponseAccepted;

                    /* Copy the payload from the MQTT library's buffer to #pucPayloadBuffer. */
                    (void)memcpy((void*)pucPayloadBuffer, (const void*)pxPublishInfo->pPayload,
                        (size_t)pxPublishInfo->payloadLength);

                    xPayloadLength = pxPublishInfo->payloadLength;
                } else if (xApi == FleetProvCborCreateCertFromCsrRejected) {
                    LogError( ( "Received rejected response from Fleet Provisioning CreateCertificateFromCsr API." ) );

                    xResponseStatus = ResponseRejected;
                } else if (xApi == FleetProvCborRegisterThingAccepted) {
                    LogInfo( ( "Received accepted response from Fleet Provisioning RegisterThing API." ) );

                    xResponseStatus = ResponseAccepted;

                    /* Copy the payload from the MQTT library's buffer to #pucPayloadBuffer. */
                    (void)memcpy((void*)pucPayloadBuffer, (const void*)pxPublishInfo->pPayload,
                        (size_t)pxPublishInfo->payloadLength);

                    xPayloadLength = pxPublishInfo->payloadLength;
                } else if (xApi == FleetProvCborRegisterThingRejected) {
                    LogError( ( "Received rejected response from Fleet Provisioning RegisterThing API." ) );

                    xResponseStatus = ResponseRejected;
                } else {
                    LogError( ( "Received message on unexpected Fleet Provisioning topic. Topic: %.*s.",
                            ( int ) pxPublishInfo->topicNameLength,
                            ( const char * ) pxPublishInfo->pTopicName ) );
                }
            }
        } else {
            vHandleOtherIncomingPacket(pxPacketInfo, pxDeserializedInfo->packetIdentifier);
            xResponseStatus = ResponseAccepted;
        }
    }
}

static void app_provinsioning_device_service(void)
{
    if (getUseFPstatus()) {

        bool xStatus = false;
        /* Buffer to hold the provisioned AWS IoT Thing name. */
        static char pcThingName[MAX_THING_NAME_LENGTH];
        /* Length of the AWS IoT Thing name. */
        static size_t xThingNameLength;
        /* Buffer for holding the CSR. */
        char pcCsr[CSR_BUFFER_LENGTH] = {0 };
        size_t xCsrLength = 0;
        /* Buffer for holding received certificate until it is saved. */
        char pcCertificate[CERT_BUFFER_LENGTH];
        size_t xCertificateLength;
        /* Buffer for holding the certificate ID. */
        char pcCertificateId[CERT_ID_BUFFER_LENGTH];
        size_t xCertificateIdLength;
        /* Buffer for holding the certificate ownership token. */
        char pcOwnershipToken[OWNERSHIP_TOKEN_BUFFER_LENGTH];
        size_t xOwnershipTokenLength;
        bool xConnectionEstablished = false;
        CK_SESSION_HANDLE xP11Session;
        CK_RV xPkcs11Ret = CKR_OK;

        /* Initialize the buffer lengths to their max lengths. */
        xCertificateLength = CERT_BUFFER_LENGTH;
        xCertificateIdLength = CERT_ID_BUFFER_LENGTH;
        xOwnershipTokenLength = OWNERSHIP_TOKEN_BUFFER_LENGTH;

        /* Initialize the PKCS #11 module */
        xPkcs11Ret = xInitializePkcs11Session(&xP11Session);

        if (xPkcs11Ret != CKR_OK) {
            LogError( ( "Failed to initialize PKCS #11." ) );
            xStatus = false;
        } else {
            xStatus = xGenerateKeyAndCsr(xP11Session,
            pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
            pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS, pcCsr,
            CSR_BUFFER_LENGTH, &xCsrLength);

            if (xStatus == false) {
                LogError( ( "Failed to generate Key and Certificate Signing Request." ) );
            }

            xPkcs11CloseSession(xP11Session);
        }

        /**** Connect to AWS IoT Core with provisioning claim credentials *****/

        /* We first use the claim credentials to connect to the broker. These
         * credentials should allow use of the RegisterThing API and one of the
         * CreateCertificatefromCsr or CreateKeysAndCertificate.
         * In this demo we use CreateCertificatefromCsr. */
        if (xStatus == true) {
            /* Set the pParams member of the network context with desired transport. */
            xNetworkContext.pxParams = &xTlsTransportParams;

            /* Attempts to connect to the AWS IoT MQTT broker. If the
             * connection fails, retries after a timeout. Timeout value will
             * exponentially increase until maximum attempts are reached. */
            LogInfo( ( "Establishing MQTT session with claim certificate..." ) );
            xStatus = xEstablishMqttSession_P11(&xMqttContext, &xNetworkContext, &xBuffer,
                prvProvisioningPublishCallback,
                pkcs11configLABEL_CLAIM_CERTIFICATE,
                pkcs11configLABEL_CLAIM_PRIVATE_KEY);
            if (xStatus == false) {
                LogError( ( "Failed to establish MQTT session." ) );
            } else {
                LogInfo( ( "Established connection with claim credentials." ) );
                xConnectionEstablished = true;
            }
        }

        /**** Call the CreateCertificateFromCsr API ***************************/

        /* We use the CreateCertificatefromCsr API to obtain a client certificate
         * for a key on the device by means of sending a certificate signing
         * request (CSR). */
        if (xStatus == true) {
            /* Subscribe to the CreateCertificateFromCsr accepted and rejected
             * topics. In this demo we use CBOR encoding for the payloads,
             * so we use the CBOR variants of the topics. */
            xStatus = prvSubscribeToCsrResponseTopics();
        }

        if (xStatus == true) {
            /* Create the request payload containing the CSR to publish to the
             * CreateCertificateFromCsr APIs. */
            xStatus = xGenerateCsrRequest(pucPayloadBuffer,
            NETWORK_BUFFER_SIZE, pcCsr, xCsrLength, &xPayloadLength);
        }

        if (xStatus == true) {
            /* Publish the CSR to the CreateCertificatefromCsr API. */
            xPublishToTopic(&xMqttContext,
            FP_CBOR_CREATE_CERT_PUBLISH_TOPIC,
            FP_CBOR_CREATE_CERT_PUBLISH_LENGTH, (char*)pucPayloadBuffer, xPayloadLength);

            if (xStatus == false) {
                LogError( ( "Failed to publish to fleet provisioning topic: %.*s.",
                        FP_CBOR_CREATE_CERT_PUBLISH_LENGTH,
                        FP_CBOR_CREATE_CERT_PUBLISH_TOPIC ) );
            }
        }

        if (xStatus == true) {
            /* From the response, extract the certificate, certificate ID, and
             * certificate ownership token. */
            xStatus = xParseCsrResponse(pucPayloadBuffer, xPayloadLength, pcCertificate, &xCertificateLength,
                pcCertificateId, &xCertificateIdLength, pcOwnershipToken, &xOwnershipTokenLength);

            if (xStatus == true) {
                LogInfo( ( "Received certificate with Id: %.*s", ( int ) xCertificateIdLength, pcCertificateId ) );
            }
        }

        if (xStatus == true) {
            /* Save the certificate into PKCS #11. */
            xStatus = xLoadCertificate(xP11Session, pcCertificate,
            pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS, xCertificateLength);
        }

        if (xStatus == true) {
            /* Unsubscribe from the CreateCertificateFromCsr topics. */
            xStatus = prvUnsubscribeFromCsrResponseTopics();
        }

        /**** Call the RegisterThing API **************************************/

        /* We then use the RegisterThing API to activate the received certificate,
         * provision AWS IoT resources according to the provisioning template, and
         * receive device configuration. */
        if (xStatus == true) {
            /* Create the request payload to publish to the RegisterThing API. */
            char tmpThingId[128] = {0, };
//time base::for testing other way
/*
    		UINT32 cur_ms = (UINT32)(get_fci_dpm_curtime()/1000);
    		da16x_sprintf(tmpThingId, "%s_%02x:%02x:%02x:%02x", FP_DEMO_ID_SUFFIX, 
    			(cur_ms&0xff000000) >> 24,
    			(cur_ms&0x00ff0000) >> 16,
    			(cur_ms&0x0000ff00) >> 8,
    			(cur_ms&0x000000ff));
    		app_print_elapse_time_ms("[%s:%d] cur_ms: %x", __func__, __LINE__, cur_ms);
*/
//mac address base[[::tested duplicated thing id for fleet provisioning
            ULONG macmsw = 0, maclsw = 0;

            getMacAddrMswLsw(WLAN0_IFACE, &macmsw, &maclsw);
            sprintf(tmpThingId, "%s_%02lX%02lX%02lx", FP_DEMO_ID_SUFFIX, ((maclsw >> 16) & 0x0ff),
                ((maclsw >> 8) & 0x0ff), ((maclsw >> 0) & 0x0ff));//[tin aws work]
            app_print_elapse_time_ms("[%s:%d] request thing id: %s", __func__, __LINE__, tmpThingId);
//]]

            xStatus = xGenerateRegisterThingRequest(pucPayloadBuffer,
            NETWORK_BUFFER_SIZE, pcOwnershipToken, xOwnershipTokenLength, tmpThingId, strlen(tmpThingId),
                &xPayloadLength);
        }

        if (xStatus == true) {
            /* Subscribe to the RegisterThing response topics. */
            xStatus = prvSubscribeToRegisterThingResponseTopics();
        }

        if (xStatus == true) {
            /* Publish the RegisterThing request. */
            xPublishToTopic(&xMqttContext, FP_CBOR_REGISTER_PUBLISH_TOPIC(PROVISIONING_TEMPLATE_NAME),
                FP_CBOR_REGISTER_PUBLISH_LENGTH(PROVISIONING_TEMPLATE_NAME_LENGTH), (char*)pucPayloadBuffer,
                xPayloadLength);

            if (xStatus == false) {
                LogError( ( "Failed to publish to fleet provisioning topic: %.*s.",
                        FP_CBOR_REGISTER_PUBLISH_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                        FP_CBOR_REGISTER_PUBLISH_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
            }
        }

        if (xStatus == true) {
            /* Extract the Thing name from the response. */
            xThingNameLength = MAX_THING_NAME_LENGTH;
            xStatus = xParseRegisterThingResponse(pucPayloadBuffer, xPayloadLength, pcThingName, &xThingNameLength);

            if (xStatus == true) {
                LogInfo( ( "Received AWS IoT Thing name: %.*s", ( int ) xThingNameLength, pcThingName ) );
                #if 0 //[tin aws work], build error, fix later 
                if (app_save_provisioned_info(pcThingName) != 0) {
                    LogError(("saving the provisioned info (\"%s\") on NVRAM: NG", pcThingName));
                } else {
                    LogInfo(("saving the provisioned info(\"%s\") saved: OK", pcThingName));
                }
                #endif 
                //re-check provisioning info from NVRAM
            }
        }

        if (xStatus == true) {
            /* Unsubscribe from the RegisterThing topics. */
            prvUnsubscribeFromRegisterThingResponseTopics();
        }

        /**** Disconnect from AWS IoT Core ************************************/

        /* As we have completed the provisioning workflow, we disconnect from
         * the connection using the provisioning claim credentials. We will
         * establish a new MQTT connection with the newly provisioned
         * credentials. */
        if (xConnectionEstablished == true) {
            //xDisconnectMqttSession_P11(&xMqttContext, &xNetworkContext);//[tin aws work], org
            xDisconnectMqttSession(&xMqttContext, &xNetworkContext);
            xConnectionEstablished = false;
        }

    }
}
//( __USE_FLEET_PROVISION__ )

#if defined(__SUPPORT_OTA__)
static OTA_UPDATE_CONFIG _fw_conf = {0, };
static OTA_UPDATE_CONFIG *fw_conf = (OTA_UPDATE_CONFIG*)&_fw_conf;

static void app_ota_fw_download_complete_notify(ota_update_type update_type, UINT status, UINT progress)
{
    if (pal_app_notify_mcu_ota(update_type, status, progress, fw_conf->auto_renew))
        return;
    switch (update_type) {
    case OTA_TYPE_RTOS: {
        IOT_DEBUG("RTOS F/W download finish. (0x%02x) \n\n", status)
        if ((status == OTA_SUCCESS)) {
#if !defined(__BLE_COMBO_REF__) //orig.
            if (fw_conf->auto_renew == 0) {
                //update index here::not worked
                //ota_update_start_renew(fw_conf);
                IOT_DEBUG("auto_renew == 0 not supported")
            } else {
                IOT_DEBUG("download new RTOS FW: OK")
            }
#else //da16600work[[::
			IOT_DEBUG("next checking BLE f/w image...")
#endif //]]da16600work
        } else {
            if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_RESULT, AWS_OTA_RESULT_NG)) {
                IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_RESULT failed\n");
            }
            vTaskDelay(1);
            IOT_DEBUG("Failed to replace with new FW. (Err : 0x%02x)", status)
            IOT_DEBUG(">>> System Reboot !!!")
            reboot_func(SYS_REBOOT);
        }
    }
        break;
#if defined(__BLE_COMBO_REF__) //da16600work[[::
#if (SDK_MAJOR == 3) && (SDK_MINOR == 2) && (SDK_REVISION >= 5)
    case OTA_TYPE_BLE_FW: {
        IOT_DEBUG("BLE FW download finished. (0x%02x) \n\n", status)
        if ((status == OTA_SUCCESS)) {
            if (fw_conf->auto_renew == 0) {
                //update index here::not worked
                //ota_update_start_renew(fw_conf);
                IOT_DEBUG("auto_renew == 0 not supported")
            } else {
                IOT_DEBUG("download new BLE FW: OK")
            }
        } else {
            if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_RESULT, AWS_OTA_RESULT_NG)) {
                IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_RESULT failed\n");
            }
            vTaskDelay(1);
            IOT_DEBUG("Failed to replace with new FW. (Err : 0x%02x)", status)
            IOT_DEBUG(">>> System Reboot !!!")
            reboot_func(SYS_REBOOT);
        }
    }
        break;
#endif

    case OTA_TYPE_MCU_FW: {
        IOT_DEBUG("BLE download finish. (0x%02x) \n\n", status)
        if ((status == OTA_SUCCESS)) {
            if (fw_conf->auto_renew == 0) {
                //update index here::not worked
                //ota_update_start_renew(fw_conf);
            } else {
                if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_RESULT, AWS_OTA_RESULT_OK)) {
                    IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_RESULT failed\n");
                }
                vTaskDelay(1);
                IOT_DEBUG("Succeeded to replace with new FW.")
            }
        } else {
            if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_RESULT, AWS_OTA_RESULT_NG)) {
                IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_RESULT failed\n");
            }
            vTaskDelay(1);
            IOT_DEBUG("Failed to replace with new FW. (Err : 0x%02x)", status)
            IOT_DEBUG(">>> System Reboot !!!")
            reboot_func(SYS_REBOOT);
        }
    }
        break;
#endif //]]da16600work
    default: {
        IOT_DEBUG("[%s:%d] update_type=%d, status=%d, progress=%d", __func__, __LINE__, update_type, status, progress);
    }
        break;
    }

    /* work todo */
}

static void app_ota_fw_renew_notify(UINT status)
{

    if (status == OTA_SUCCESS) {
        if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_RESULT, AWS_OTA_RESULT_OK)) {
            IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_RESULT failed\n");
        }
        vTaskDelay(1);
        IOT_DEBUG("Succeeded to replace with new FW.")
    } else {
        if (api_usr_nvram_write_int(AWS_NVRAM_CONFIG_OTA_RESULT, AWS_OTA_RESULT_NG)) {
            IOT_ERROR("write AWS_NVRAM_CONFIG_OTA_RESULT failed\n");
        }
        vTaskDelay(1);
        IOT_DEBUG("Failed to replace with new FW. (Err : 0x%02x)", status)
        IOT_DEBUG(">>> System Reboot !!!")
        reboot_func(SYS_REBOOT);
    }

    /* work todo */
}

static UINT32 aws_ota_fw_update(char *_fw_url)
{
    UINT32 status = OTA_SUCCESS;

    memset(fw_conf, 0x00, sizeof(OTA_UPDATE_CONFIG));
    if (!pal_app_check_is_update_mcu(_fw_url, fw_conf)) {
        /* Setting the type to be updated */
#if (SDK_MAJOR == 3) && (SDK_MINOR == 2) && (SDK_REVISION >= 5)
#if defined (__BLE_COMBO_REF__) //da1600work::FW image for BLE
        fw_conf->update_type = OTA_TYPE_BLE_COMBO;
#else
        fw_conf->update_type = OTA_TYPE_RTOS;
#endif
#else
        fw_conf->update_type = OTA_TYPE_RTOS;
#endif

        /* uri setting example - Change it to suit your environment. */
        //sprintf(ota_path_url_rtos, "%s%s", _fw_url, RTOS_NAME);//[tin aws work]
#if (SDK_MAJOR == 3) && (SDK_MINOR == 2) && (SDK_REVISION >= 5)
        memcpy(fw_conf->url, ota_path_url_rtos, strlen(ota_path_url_rtos));
        IOT_DEBUG(" %s url %s", "RTOS", fw_conf->url)
#else
        //memcpy(fw_conf->uri, ota_path_url_rtos, strlen(ota_path_url_rtos));//[tin aws work]
        //IOT_DEBUG(" %s url %s", "RTOS", fw_conf->uri)//[tin aws work]
#endif

#if defined (__BLE_COMBO_REF__) //da1600work::FW image for BLE
		snprintf(ota_path_url_ble, MAX_URL_LEN, "%s%s", _fw_url, BLE_NAME);
#if (SDK_MAJOR == 3) && (SDK_MINOR == 2) && (SDK_REVISION >= 5)
        memcpy(fw_conf->url_ble_fw, ota_path_url_ble, strlen(ota_path_url_ble));
#else
        memcpy(fw_conf->uri_other_fw, ota_path_url_ble, strlen(ota_path_url_ble));
#endif
		IOT_DEBUG(" BLE url %s", ota_path_url_ble)
#endif // __BLE_COMBO_REF__
    }

    /* FW renew (reboot) after successful  download */
    fw_conf->auto_renew = 1;

    /* Call when download is complete (success or fail)  */
    fw_conf->download_notify = app_ota_fw_download_complete_notify;

    /* Called when the renew(change boot index) is complete (If it succeeds, it will reboot automatically.)  */
    fw_conf->renew_notify = app_ota_fw_renew_notify;

    /* get ip address in advance */
    status = ota_update_start_download(fw_conf);
    if (status) {
        IOT_ERROR("OTA update start fail (0x%02x)\n", status);
    }

    return status;
}
#endif	/* __SUPPORT_OTA__ */

