#include <gtest/gtest.h>
#include "TextToSpeech.h"
#include "TextToSpeechImplementation.h"

#include "ServiceMock.h"
#include "COMLinkMock.h"
#include "FactoriesImplementation.h"
#include "WorkerPoolImplementation.h"

using namespace WPEFramework;
using ::testing::Test;
using ::testing::NiceMock;

namespace {
const string config = _T("TextToSpeech");
const string callSign = _T("org.rdk.TextToSpeech");
const string webPrefix = _T("/Service/TextToSpeech");
const string volatilePath = _T("/tmp/");
const string dataPath = _T("/tmp/");
}

class TTSTest : public Test{
protected:
    Core::ProxyType<Plugin::TextToSpeech> plugin;
    Core::JSONRPC::Handler& handler;
    Core::JSONRPC::Connection connection;
    Core::ProxyType<WorkerPoolImplementation> workerPool;

    TTSTest()
        : plugin(Core::ProxyType<Plugin::TextToSpeech>::Create())
        , handler(*(plugin))
        , connection(1, 0)
        , workerPool(Core::ProxyType<WorkerPoolImplementation>::Create(
            2, Core::Thread::DefaultStackSize(), 16)) {
    }

    virtual ~TTSTest() = default;
};

class TTSInitializedTest : public TTSTest {
protected:
    NiceMock<FactoriesImplementation> factoriesImplementation;
    NiceMock<ServiceMock> service;
    NiceMock<COMLinkMock> comLinkMock;
    PluginHost::IDispatcher* dispatcher;
    Core::ProxyType<Plugin::TextToSpeechImplementation> TextToSpeechImplementation;
    string response;

    TTSInitializedTest() : TTSTest() {
        TextToSpeechImplementation = Core::ProxyType<Plugin::TextToSpeechImplementation>::Create();

        ON_CALL(service, ConfigLine())
            .WillByDefault(::testing::Return("{}"));
        ON_CALL(service, WebPrefix())
            .WillByDefault(::testing::Return(webPrefix));
        ON_CALL(service, VolatilePath())
            .WillByDefault(::testing::Return(volatilePath));
        ON_CALL(service, Callsign())
            .WillByDefault(::testing::Return(callSign));
                ON_CALL(service, DataPath())
            .WillByDefault(::testing::Return(dataPath));
        ON_CALL(service, COMLink())
            .WillByDefault(::testing::Return(&comLinkMock));
        ON_CALL(comLinkMock, Instantiate(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
            .WillByDefault(::testing::Return(TextToSpeechImplementation));

        PluginHost::IFactories::Assign(&factoriesImplementation);
        Core::IWorkerPool::Assign(&(*workerPool));
        workerPool->Run();

        dispatcher = static_cast<PluginHost::IDispatcher*>(
            plugin->QueryInterface(PluginHost::IDispatcher::ID));
        dispatcher->Activate(&service);
    }

    virtual ~TTSInitializedTest() override {
        plugin.Release();
        TextToSpeechImplementation.Release();
        Core::IWorkerPool::Assign(nullptr);
        workerPool.Release();
        PluginHost::IFactories::Assign(nullptr);
        dispatcher->Deactivate();
        dispatcher->Release();
    }
};

TEST_F(TTSInitializedTest,RegisteredMethods) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("enabletts")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("cancel")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("getapiversion")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("getspeechstate")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("getttsconfiguration")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("isspeaking")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("isttsenabled")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("listvoices")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("pause")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("resume")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("setttsconfiguration")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("speak")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("setACL")));
}

TEST_F(TTSInitializedTest,Test_EnableTTS_Default_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("enabletts"), _T("{\"enabletts\": \"true\"}"), response));
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"TTS_Status\":0")));
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"success\":true")));
}

TEST_F(TTSInitializedTest,Test_EnableTTS_True_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("enabletts"), _T("{\"enabletts\": true }"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("isttsenabled"), _T(""), response));
    EXPECT_EQ(response, _T("{\"isenabled\":true,\"TTS_Status\":0,\"success\":true}"));
}

TEST_F(TTSInitializedTest,Test_EnableTTS_False_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("enabletts"), _T("{\"enabletts\": false }"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("isttsenabled"), _T(""), response));
    EXPECT_EQ(response, _T("{\"isenabled\":false,\"TTS_Status\":0,\"success\":true}"));
}

TEST_F(TTSInitializedTest,Test_GetAPIVersion_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getapiversion"), _T(""), response));
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"version\":1")));
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"success\":true")));
}

TEST_F(TTSInitializedTest,Test_IsTTSEnabled_Default_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("isttsenabled"), _T(""), response));
    EXPECT_EQ(response, _T("{\"isenabled\":false,\"TTS_Status\":0,\"success\":true}"));
}

/*******************************************************************************************************************
 * Test function for listVoices
 * SpeechState          :
 *                Returns voice based on language
 *
 *                @return Response object contains speaking and success 
 * Use case coverage:
 *                @Success :
 *                @Failure :
 ********************************************************************************************************************/
/**
 * @name  : Test_IsListVoicesEmpty_Success
 * @brief : Returns speaking(true,false) of the given speechid 
 *
 * @param[in]   :  language
 * @return      :  ERROR_NONE
 */
TEST_F(TTSInitializedTest,Test_IsListVoicesEmpty_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("listvoices"), _T("{\"language\":\"en-US\"}"), response));
    EXPECT_EQ(response, _T("{\"voices\":[],\"TTS_Status\":0,\"success\":true}"));
}

/**
 * @name  : ListVoicesSetEmptyLanguage
 * @brief : Set language as empty and check whether it return error
 *
 * @param[in]   :  Set "" in language
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, ListVoicesSetEmptyLanguage) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("listvoices"), _T("{\"language\": \"\"}"), response));
}

/**
 * @name  : ListVoicesSetWhiteSpaceLanguage
 * @brief : Set language as " " and check whether it return error
 *
 * @param[in]   :  Set " " in language
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, ListVoicesSetWhiteSpaceAsLanguage) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("listvoices"), _T("{\"language\": \"  \"}"), response));
}

/**
 * @name  : ListVoicesSetNumberAsLanguage
 * @brief : Set language as Number and check whether it return error
 *
 * @param[in]   :  Set "" in language
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, ListVoicesSetNumberAsLanguage) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("listvoices"), _T("{\"language\": 01}"), response));
}

/**
 * @name  : ListVoicesSetNullLanguage
 * @brief : Set language as NULL and check whether it return error
 *
 * @param[in]   :  Set NULL language
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, ListVoicesSetNullLanguage) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("listvoices"), _T("{\"language\": NULL}"), response));
}

TEST_F(TTSInitializedTest,Test_Speak_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection,
        _T("setttsconfiguration"),
        _T("{\"language\": \"en-US\",\"voice\": \"carol\","
            "\"ttsendpointsecured\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\","
            "\"ttsendpoint\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\"}"
        ),
        response
    ));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("speak"), _T("{\"text\": \"speech_123\"}"), response));
    sleep(1);

    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"speechid\"")));
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"TTS_Status\":0")));
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"success\":true")));
}
/*******************************************************************************************************************
 * Test function for IsSpeaking
 * SpeechState          :
 *                Returns whether current speechid is speaking or not
 *
 *                @return Response object contains speaking and success 
 * Use case coverage:
 *                @Success :
 *                @Failure :
 ********************************************************************************************************************/
/**
 * @name  : Test_IsSpeaking_Success
 * @brief : Returns speaking(true,false) of the given speechid 
 *
 * @param[in]   :  speechid
 * @return      :  ERROR_NONE
 */
TEST_F(TTSInitializedTest,Test_IsSpeaking_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("isspeaking"), _T("{\"speechid\": 1}"), response));
    EXPECT_EQ(response, _T("{\"speaking\":false,\"TTS_Status\":0,\"success\":true}"));
}

/**
 * @name  : IsSpeakingEmptySpeechId
 * @brief : Given a empty speechid it should return error
 *
 * @param[in]   :  "" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,IsSpeakingEmptySpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("isspeaking"), _T("{\"speechid\": }"), response));
}

/**
 * @name  : IsSpeakingStringAsSpeechId
 * @brief : Given a string speechid it should return error
 *
 * @param[in]   :  "hello" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,IsSpeakingStringAsSpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("isspeaking"), _T("{\"speechid\": \"hello\"}"), response));
}

/*******************************************************************************************************************
 * Test function for GetSpeechState
 * SpeechState          :
 *                Returns the SpeechState of the given speechid
 *
 *                @return Response object contains speechstate and success 
 * Use case coverage:
 *                @Success :
 *                @Failure :
 ********************************************************************************************************************/
/**
 * @name  : Test_SpeechState_Success
 * @brief : Returns the SpeechState of the given speechid 
 *
 * @param[in]   :  speechid
 * @return      :  ERROR_NONE
 */

TEST_F(TTSInitializedTest,Test_GetSpeechState_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getspeechstate"), _T("{\"speechid\": 1}"), response));
    EXPECT_EQ(response, _T("{\"speechstate\":3,\"TTS_Status\":0,\"success\":true}"));
}

/**
 * @name  : GetSpeechStateEmptySpeechId
 * @brief : Given a empty speechid it should return error
 *
 * @param[in]   :  "" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,GetSpeechStateEmptySpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("getspeechstate"), _T("{\"speechid\": }"), response));
}

/**
 * @name  : GetSpeechStateStringAsSpeechId
 * @brief : Given a string speechid it should return error
 *
 * @param[in]   :  "hello" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,GetSpeechStateStringAsSpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("getspeechstate"), _T("{\"speechid\": \"hello\"}"), response));
}

/*******************************************************************************************************************
 * Test function for Cancel
 * cancel          :
 *                Cancel the speech currently happening
 *
 *                @return Response object contains TTS_Status and success 
 * Use case coverage:
 *                @Success :
 *                @Failure :
 ********************************************************************************************************************/
/**
 * @name  : Test_Cancel_Success
 * @brief : Given a speechid it should cancel it 
 *
 * @param[in]   :  Valid configuration
 * @return      :  ERROR_NONE
 */

TEST_F(TTSInitializedTest,Test_Cancel_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("cancel"), _T("{\"speechid\": 1}"), response));
    EXPECT_EQ(response, _T("{\"TTS_Status\":0,\"success\":true}"));
}

/**
 * @name  : CancelEmptySpeechId
 * @brief : Given a speechid it should return error
 *
 * @param[in]   :  "" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,CancelEmptySpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("cancel"), _T("{\"speechid\": }"), response));
}

/**
 * @name  : CancelStringAsSpeechId
 * @brief : Given a string speechid it should return error
 *
 * @param[in]   :  "hello" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,CancelStringAsSpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("cancel"), _T("{\"speechid\": \"hello\"}"), response));
}

/*******************************************************************************************************************
 * Test function for Pause
 * cancel          :
 *                Cancel the speech currently happening
 *
 *                @return Response object contains TTS_Status and success 
 * Use case coverage:
 *                @Success :
 *                @Failure :
 ********************************************************************************************************************/
/**
 * @name  : Test_Pause_Success
 * @brief : Given a speechid it should cancel it 
 *
 * @param[in]   :  Valid configuration
 * @return      :  ERROR_NONE
 */

/*TEST_F(TTSInitializedTest,Test_Pause_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("pause"), _T("{\"speechid\": 1}"), response));
    EXPECT_EQ(response, _T("{\"TTS_Status\":1,\"success\":false}"));
}*/

/**
 * @name  : PauseEmptySpeechId
 * @brief : Given a speechid it should return error
 *
 * @param[in]   :  "" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,PauseEmptySpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("pause"), _T("{\"speechid\":\"\"}"), response));
}

/**
 * @name  : PauseStringAsSpeechId
 * @brief : Given a string speechid it should return error
 *
 * @param[in]   :  "hello" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,PauseStringAsSpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("pause"), _T("{\"speechid\": \"hello\"}"), response));
}


/*******************************************************************************************************************
 * Test function for resume
 * resume          :
 *                resume the speech which is resumed
 *
 *                @return Response object contains TTS_Status and success 
 * Use case coverage:
 *                @Success :
 *                @Failure :
 ********************************************************************************************************************/
/**
 * @name  : Test_Resume_Success
 * @brief : Given a speechid it should resume it 
 *
 * @param[in]   :  Valid configuration
 * @return      :  ERROR_NONE
 */

/*TEST_F(TTSInitializedTest,Test_Resume_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("resume"), _T("{\"speechid\": 1}"), response));
    EXPECT_EQ(response, _T("{\"TTS_Status\":1,\"success\":false}"));
}*/

/**
 * @name  : ResumeEmptySpeechId
 * @brief : Given a speechid it should return error
 *
 * @param[in]   :  "" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,ResumeEmptySpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("resume"), _T("{\"speechid\":\"\"}"), response));
}

/**
 * @name  : ResumeStringAsSpeechId
 * @brief : Given a string speechid it should return error
 *
 * @param[in]   :  "hello" in speechId
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest,ResumeStringAsSpeechId) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("resume"), _T("{\"speechid\": \"hello\"}"), response));
}
/*******************************************************************************************************************
 * Test function for :setttsconfiguration
 * setttsconfiguration :
 *                Set The TTS configurations based on params  
 *
 *                @return Response object contains TTS_Status and success 
 * Use case coverage:
 *                @Success :
 *                @Failure :
 ********************************************************************************************************************/
/**
 * @name  : SetTTSConfiguration
 * @brief : Given a valid JSON request check whether response is success
 *
 * @param[in]   :  Valid configuration
 * @return      :  ERROR_NONE
 */
TEST_F(TTSInitializedTest, SetTTSConfiguration) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(
        connection,
        _T("setttsconfiguration"),
        _T("{\"language\": \"en-US\",\"voice\": \"carol\","
            "\"ttsendpoint\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\","
            "\"ttsendpointsecured\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\"}"
        ),
        response
    ));

    EXPECT_EQ(response, _T("{\"TTS_Status\":0,\"success\":true}"));
}



/**
 * @name  : SetInvalidTTSEndpoint
 * @brief : Set Invalid URL in ttsendpoint and check it return error
 *
 * @param[in]   :  Set invalid url in ttsendpoint
 * @expected    :  ERROR_GENERAL  
 */

TEST_F(TTSInitializedTest, SetInvalidTTSEndpoint) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"language\": \"en-US\",\"voice\": \"carol\",\"ttsendpoint\":\"invalid1@#\",\"ttsendpointsecured\":\"http://localhost:50050/nuanceEve/tts?\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ttsEndPointPos = response.find("\"ttsendpoint\"");

    if (ttsEndPointPos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t ttsEndpointStart = response.find(':', ttsEndPointPos ) + 1;
        size_t ttsEndpointEnd = response.find(',', ttsEndPointPos );

        std::string ttsSubstring = response.substr(ttsEndpointStart ,ttsEndpointEnd  - ttsEndpointStart );

        std::cout << "ttsEndpoint: " << ttsSubstring  << std::endl;
        EXPECT_EQ(ttsSubstring ,"\"\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}

/**
 * @name  : SetInvalidSecuredTTSEndpoint
 * @brief : Set Invalid URL in ttssecuredendpoint and check it return error
 *
 * @param[in]   :  Set invalid url in ttsendpoint
 * @expected    :  ERROR_GENERAL  
 */

TEST_F(TTSInitializedTest, SetInvalidtSecuredTTSEndpoint) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"language\": \"en-US\",\"voice\": \"carol\",\"ttsendpoint\":\"http://localhost:50050/nuanceEve/tts?\",\"ttsendpointsecured\":\"invalid1@#\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ttsEndPointPos = response.find("\"ttsendpointsecured\"");

    if (ttsEndPointPos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t ttsEndpointStart = response.find(':', ttsEndPointPos ) + 1;
        size_t ttsEndpointEnd = response.find(',', ttsEndPointPos );

        std::string ttsSubstring = response.substr(ttsEndpointStart ,ttsEndpointEnd  - ttsEndpointStart );

        std::cout << "ttsEndpointSecured: " << ttsSubstring  << std::endl;
        EXPECT_EQ(ttsSubstring ,"\"\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}

/**
 * @name  : SetEmptyTTSEndpoint
 * @brief : Set Empty URL in ttsendpoint and check it returns error
 *
 * @param[in]   :  Set "" in ttsendpoint
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetEmptyTTSEndpoint) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"ttsendpoint\":\"\"}"), response));
    //EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    //EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"ttsenpoint\":\"\"")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ttsEndPointPos = response.find("\"ttsendpoint\"");

    if (ttsEndPointPos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t ttsEndpointStart = response.find(':', ttsEndPointPos ) + 1;
        size_t ttsEndpointEnd = response.find(',', ttsEndPointPos );

        std::string ttsSubstring = response.substr(ttsEndpointStart ,ttsEndpointEnd  - ttsEndpointStart );

        std::cout << "ttsEndpoint: " << ttsSubstring  << std::endl;
        EXPECT_EQ(ttsSubstring ,"\"\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}
/**
 * @name  : SetEmptySecuredTTSEndpoint
 * @brief : Set Empty URL in ttssecuredendpoint and check it returns error
 *
 * @param[in]   :  Set "" in ttsendpoint
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetEmptySecuredTTSEndpoint) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"ttssecuredendpoint\":\"\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ttsEndPointPos = response.find("\"ttsendpointsecured\"");

    if (ttsEndPointPos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t ttsEndpointStart = response.find(':', ttsEndPointPos ) + 1;
        size_t ttsEndpointEnd = response.find(',', ttsEndPointPos );

        std::string ttsSubstring = response.substr(ttsEndpointStart ,ttsEndpointEnd  - ttsEndpointStart );

        std::cout << "ttsEndpointSecured: " << ttsSubstring  << std::endl;
        EXPECT_EQ(ttsSubstring ,"\"\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}
/**
 * @name  : SetNullTTSEndpoint
 * @brief : Set NULL  in ttsendpoint and check it returns error
 *
 * @param[in]   :  Set NULL in ttsendpoint
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetNULLTTSEndpoint) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"ttsendpoint\": null}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ttsEndPointPos = response.find("\"ttsendpoint\"");

    if (ttsEndPointPos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t ttsEndpointStart = response.find(':', ttsEndPointPos ) + 1;
        size_t ttsEndpointEnd = response.find(',', ttsEndPointPos );

        std::string ttsSubstring = response.substr(ttsEndpointStart ,ttsEndpointEnd  - ttsEndpointStart );

        std::cout << "ttsEndpoint: " << ttsSubstring  << std::endl;
        EXPECT_EQ(ttsSubstring ,"\"\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}

/**
 * @name  : SetNULLSecuredTTSEndpoint
 * @brief : Set NULL in ttssecuredendpoint and check it returns error
 *
 * @param[in]   :  Set NULL in ttsendpoint
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetNULLSecuredTTSEndpoint) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"ttssecuredendpoint\": null}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ttsEndPointPos = response.find("\"ttsendpointsecured\"");

    if (ttsEndPointPos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t ttsEndpointStart = response.find(':', ttsEndPointPos ) + 1;
        size_t ttsEndpointEnd = response.find(',', ttsEndPointPos );

        std::string ttsSubstring = response.substr(ttsEndpointStart ,ttsEndpointEnd  - ttsEndpointStart );

        std::cout << "ttsEndpointSecured: " << ttsSubstring  << std::endl;
        EXPECT_EQ(ttsSubstring ,"\"\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}
/**
 * @name  : SetStringAsVolume
 * @brief : Set string in Volume and check it returns error
 *
 * @param[in]   :  Set "invalid" in Volume
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetStringAsVolume) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"volume\": \"invalid\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t volumePos = response.find("\"volume\"");

    if (volumePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t volumeStart = response.find(':', volumePos ) + 1;
        size_t volumeEnd = response.find(',', volumePos );

        std::string volumeSubstring = response.substr(volumeStart ,volumeEnd  - volumeStart );

        std::cout << "volume: " << volumeSubstring  << std::endl;
        EXPECT_EQ(volumeSubstring ,"\"95\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}

/**
 * @name  : SetVolumeLessThanMinValue
 * @brief : Set volume as -1 and check whether it return error
 *
 * @param[in]   :  Set -1 in Volume
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetVolumeLessThanMinValue) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"volume\": -1}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t volumePos = response.find("\"volume\"");

    if (volumePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t volumeStart = response.find(':', volumePos ) + 1;
        size_t volumeEnd = response.find(',', volumePos );

        std::string volumeSubstring = response.substr(volumeStart ,volumeEnd  - volumeStart );

        std::cout << "volume: " << volumeSubstring  << std::endl;
        EXPECT_EQ(volumeSubstring ,"\"95\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}

/**
 * @name  : SetVolumeLessThanMaxValue
 * @brief : Set volume as 101 and check whether it return error
 *
 * @param[in]   :  Set 101 in Volume
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetVolumeGreaterThanMaxValue) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"volume\": 101}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t volumePos = response.find("\"volume\"");

    if (volumePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t volumeStart = response.find(':', volumePos ) + 1;
        size_t volumeEnd = response.find(',', volumePos );

        std::string volumeSubstring = response.substr(volumeStart ,volumeEnd  - volumeStart );

        std::cout << "volume: " << volumeSubstring  << std::endl;
        EXPECT_EQ(volumeSubstring ,"\"95\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}

/**
 * @name  : SetEmptyVolume
 * @brief : Set volume as empty and check whether it return error
 *
 * @param[in]   :  Set  in Volume
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetEmptyVolume) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"volume\":}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t volumePos = response.find("\"volume\"");

    if (volumePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t volumeStart = response.find(':', volumePos ) + 1;
        size_t volumeEnd = response.find(',', volumePos );

        std::string volumeSubstring = response.substr(volumeStart ,volumeEnd  - volumeStart );

        std::cout << "volume: " << volumeSubstring  << std::endl;
        EXPECT_EQ(volumeSubstring ,"\"95\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'ttsendpoint' not found in the response.";
    }
}


TEST_F(TTSInitializedTest,Test_SetACL_Success) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":\"speak\",\"apps\":[\"WebAPP1\"]}]}"),
        response
    ));

    EXPECT_EQ(response, _T("{\"success\":true}"));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(
        connection,
        _T("setttsconfiguration"),
        _T("{\"language\": \"en-US\",\"voice\": \"carol\","
            "\"ttsendpoint\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\","
            "\"ttsendpointsecured\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\"}"
        ),
        response
    ));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("speak"), _T("{\"text\": \"speech_123\",\"callsign\":\"WebAPP1\"}"), response));
    sleep(1);
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"speechid\"")));
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"TTS_Status\":0")));
    EXPECT_THAT(response, ::testing::ContainsRegex(_T("\"success\":true")));
}
/**
 * @name  : SetStringAsRate
 * @brief : Set string in rate and check it returns error
 *
 * @param[in]   :  Set "invalid" in rate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetStringAsRate) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"rate\": \"invalid\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ratePos = response.find("\"rate\"");

    if (ratePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t rateStart = response.find(':', ratePos ) + 1;
        size_t rateEnd = response.find(',', ratePos );

        std::string rateSubstring = response.substr(rateStart ,rateEnd  - rateStart );

        std::cout << "rate: " << rateSubstring  << std::endl;
        EXPECT_EQ(rateSubstring ,"40");
     } else {
        EXPECT_TRUE(false) << "Error: 'rate' not found in the response.";
    }
}

/**
 * @name  : SetRateLessThanMinValue
 * @brief : Set rate as -1 and check whether it return error
 *
 * @param[in]   :  Set -1 in rate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetRateLessThanMinValue) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"rate\": -1}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ratePos = response.find("\"rate\"");

    if (ratePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t rateStart = response.find(':', ratePos ) + 1;
        size_t rateEnd = response.find(',', ratePos );

        std::string rateSubstring = response.substr(rateStart ,rateEnd  - rateStart );

        std::cout << "rate: " << rateSubstring  << std::endl;
        EXPECT_EQ(rateSubstring ,"40");
     } else {
        EXPECT_TRUE(false) << "Error: 'rate' not found in the response.";
    }
}

/**
 * @name  : SetRateGreaterThanMaxValue
 * @brief : Set rate as 101 and check whether it return error
 *
 * @param[in]   :  Set 101 in rate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetRateGreaterThanMaxValue) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"rate\": 101}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ratePos = response.find("\"rate\"");

    if (ratePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t rateStart = response.find(':', ratePos ) + 1;
        size_t rateEnd = response.find(',', ratePos );

        std::string rateSubstring = response.substr(rateStart ,rateEnd  - rateStart );

        std::cout << "rate: " << rateSubstring  << std::endl;
        EXPECT_EQ(rateSubstring ,"40");
     } else {
        EXPECT_TRUE(false) << "Error: 'rate' not found in the response.";
    }
}

/**
 * @name  : SetEmptyRate
 * @brief : Set rate as empty and check whether it return error
 *
 * @param[in]   :  Set  in rate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetEmptyRate) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"rate\":\"\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t ratePos = response.find("\"rate\"");

    if (ratePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t rateStart = response.find(':', ratePos ) + 1;
        size_t rateEnd = response.find(',', ratePos );

        std::string rateSubstring = response.substr(rateStart ,rateEnd  - rateStart );

        std::cout << "rate: " << rateSubstring  << std::endl;
        EXPECT_EQ(rateSubstring ,"40");
     } else {
        EXPECT_TRUE(false) << "Error: 'rate' not found in the response.";
    }
}

/**
 * @name  : SetStringAsPrimvolduckpercent
 * @brief : Set string in primvolduckpercent and check it returns error
 *
 * @param[in]   :  Set "invalid" in primvolduckpercent
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetStringAsprimvolduckpercent) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"primvolduckpercent\": \"invalid\"}"), response));
}

/**
 * @name  : SetPrimvolduckpercentLessThanMinValue
 * @brief : Set primvolduckpercent as -1 and check whether it return error
 *
 * @param[in]   :  Set -1 in primvolduckpercent
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetPrimvolduckpercentLessThanMinValue) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"primvolduckpercent\": -1}"), response));
}

/**
 * @name  : SetPrimvolduckpercentGreaterThanMaxValue
 * @brief : Set primvolduckpercent as 101 and check whether it return error
 *
 * @param[in]   :  Set 101 in primvolduckpercent
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetPrimvolduckpercentGreaterThanMaxValue) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"primvolduckpercent\": 101}"), response));
}

/**
 * @name  : SetEmptyPrimvolduckpercent
 * @brief : Set primvolduckpercent as empty and check whether it return error
 *
 * @param[in]   :  Set  in primvolduckpercent
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetEmptyPrimvolduckpercent) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"primvolduckpercent\": }"), response));
}

/**
 * @name  : SetEmptySpeechRate
 * @brief : Set speechrate as empty and check whether it return error
 *
 * @param[in]   :  Set "" in speechrate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetEmptySpeechRate) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"speechrate\": \"\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t speechRatePos = response.find("\"speechrate\"");

    if (speechRatePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t speechRatePosStart = response.find(':', speechRatePos ) + 1;
        size_t speechRatePosEnd = response.find(',', speechRatePos );

        std::string speechRateSubstring = response.substr(speechRatePosStart ,speechRatePosEnd  - speechRatePosStart);

        std::cout << "speechrate: " << speechRateSubstring  << std::endl;
        EXPECT_EQ(speechRateSubstring ,"\"medium\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'speechrate' not found in the response.";
    }
}

/**
 * @name  : SetWhiteSpaceSpeechRate
 * @brief : Set speechrate as " " and check whether it return error
 *
 * @param[in]   :  Set " " in speechrate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetWhiteSpaceAsSpeechRate) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"speechrate\": \"  \"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t speechRatePos = response.find("\"speechrate\"");

    if (speechRatePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t speechRatePosStart = response.find(':', speechRatePos ) + 1;
        size_t speechRatePosEnd = response.find(',', speechRatePos );

        std::string speechRateSubstring = response.substr(speechRatePosStart ,speechRatePosEnd  - speechRatePosStart);

        std::cout << "speechrate: " << speechRateSubstring  << std::endl;
        EXPECT_EQ(speechRateSubstring ,"\"medium\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'speechrate' not found in the response.";
    }
}

/**
 * @name  : SetNumberAsSpeechRate
 * @brief : Set speechrate as Number and check whether it return error
 *
 * @param[in]   :  Set "" in speechrate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetNumberAsSpeechRate) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"speechrate\": 01}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t speechRatePos = response.find("\"speechrate\"");

    if (speechRatePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t speechRatePosStart = response.find(':', speechRatePos ) + 1;
        size_t speechRatePosEnd = response.find(',', speechRatePos );

        std::string speechRateSubstring = response.substr(speechRatePosStart ,speechRatePosEnd  - speechRatePosStart);

        std::cout << "speechrate: " << speechRateSubstring  << std::endl;
        EXPECT_EQ(speechRateSubstring ,"\"medium\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'speechrate' not found in the response.";
    }
}

/**
 * @name  : SetNullSpeechRate
 * @brief : Set speechrate as NULL and check whether it return error
 *
 * @param[in]   :  Set NULL speechrate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetNullSpeechRate) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"speechrate\": null}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t speechRatePos = response.find("\"speechrate\"");

    if (speechRatePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t speechRatePosStart = response.find(':', speechRatePos ) + 1;
        size_t speechRatePosEnd = response.find(',', speechRatePos );

        std::string speechRateSubstring = response.substr(speechRatePosStart ,speechRatePosEnd  - speechRatePosStart);

        std::cout << "speechrate: " << speechRateSubstring  << std::endl;
        EXPECT_EQ(speechRateSubstring ,"\"medium\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'speechrate' not found in the response.";
    }
}

/**
 * @name  : SetInvalidSpeechRate
 * @brief : Set speechrate as Invalid It should be one of the following [slow,medium,fast,faster]
 *
 * @param[in]   :  Set invalid  speechrate
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetInvalidSpeechRate) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"speechrate\": \"invalid\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t speechRatePos = response.find("\"speechrate\"");

    if (speechRatePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t speechRatePosStart = response.find(':', speechRatePos ) + 1;
        size_t speechRatePosEnd = response.find(',', speechRatePos );

        std::string speechRateSubstring = response.substr(speechRatePosStart ,speechRatePosEnd  - speechRatePosStart);

        std::cout << "speechrate: " << speechRateSubstring  << std::endl;
        EXPECT_EQ(speechRateSubstring ,"\"medium\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'speechrate' not found in the response.";
    }
}

/**
 * @name  : SetEmptyLanguage
 * @brief : Set language as empty and check whether it return error
 *
 * @param[in]   :  Set "" in language
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetEmptyLanguage) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"language\": \"\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t languagePos = response.find("\"language\"");

    if (languagePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t languagePosStart = response.find(':', languagePos ) + 1;
        size_t languagePosEnd = response.find(',', languagePos );

        std::string languageSubstring = response.substr(languagePosStart ,languagePosEnd  - languagePosStart);

        std::cout << "language: " << languageSubstring  << std::endl;
        EXPECT_EQ(languageSubstring ,"\"en-US\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'language' not found in the response.";
    }
}

/**
 * @name  : SetWhiteSpaceLanguage
 * @brief : Set language as " " and check whether it return error
 *
 * @param[in]   :  Set " " in language
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetWhiteSpaceAsLanguage) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"language\": \"  \"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t languagePos = response.find("\"language\"");

    if (languagePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t languagePosStart = response.find(':', languagePos ) + 1;
        size_t languagePosEnd = response.find(',', languagePos );

        std::string languageSubstring = response.substr(languagePosStart ,languagePosEnd  - languagePosStart);

        std::cout << "language: " << languageSubstring  << std::endl;
        EXPECT_EQ(languageSubstring ,"\"en-US\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'language' not found in the response.";
    }
}

/**
 * @name  : SetNumberAsLanguage
 * @brief : Set language as Number and check whether it return error
 *
 * @param[in]   :  Set "" in language
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetNumberAsLanguage) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"language\": 01}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t languagePos = response.find("\"language\"");

    if (languagePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t languagePosStart = response.find(':', languagePos ) + 1;
        size_t languagePosEnd = response.find(',', languagePos );

        std::string languageSubstring = response.substr(languagePosStart ,languagePosEnd  - languagePosStart);

        std::cout << "language: " << languageSubstring  << std::endl;
        EXPECT_EQ(languageSubstring ,"\"en-US\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'language' not found in the response.";
    }
}

/**
 * @name  : SetNullLanguage
 * @brief : Set language as NULL and check whether it return error
 *
 * @param[in]   :  Set NULL language
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetNullLanguage) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"language\": NULL}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t languagePos = response.find("\"language\"");

    if (languagePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t languagePosStart = response.find(':', languagePos ) + 1;
        size_t languagePosEnd = response.find(',', languagePos );

        std::string languageSubstring = response.substr(languagePosStart ,languagePosEnd  - languagePosStart);

        std::cout << "language: " << languageSubstring  << std::endl;
        EXPECT_EQ(languageSubstring ,"\"en-US\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'language' not found in the response.";
    }
}

/**
 * @name  : SetEmptyVoice
 * @brief : Set voice as empty and check whether it return error
 *
 * @param[in]   :  Set "" in voice
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetEmptyVoice) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"voice\": \"\"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t voicePos = response.find("\"voice\"");

    if (voicePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t voicePosStart = response.find(':', voicePos ) + 1;
        size_t voicePosEnd = response.find(',', voicePos );

        std::string voiceSubstring = response.substr(voicePosStart ,voicePosEnd  - voicePosStart );

        std::cout << "voice: " << voiceSubstring  << std::endl;
        EXPECT_EQ(voiceSubstring ,"\"carol\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'voice' not found in the response.";
    }
}

/**
 * @name  : SetWhiteSpaceVoice
 * @brief : Set voice as " " and check whether it return error
 *
 * @param[in]   :  Set " " in voice
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetWhiteSpaceAsVoice) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"voice\": \"  \"}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t voicePos = response.find("\"voice\"");

    if (voicePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t voicePosStart = response.find(':', voicePos ) + 1;
        size_t voicePosEnd = response.find(',', voicePos );

        std::string voiceSubstring = response.substr(voicePosStart ,voicePosEnd  - voicePosStart );

        std::cout << "voice: " << voiceSubstring  << std::endl;
        EXPECT_EQ(voiceSubstring ,"\"carol\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'voice' not found in the response.";
    }
}

/**
 * @name  : SetNumberAsVoice
 * @brief : Set voice as Number and check whether it return error
 *
 * @param[in]   :  Set "" in voice
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetNumberAsVoice) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"voice\": 01}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t voicePos = response.find("\"voice\"");

    if (voicePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t voicePosStart = response.find(':', voicePos ) + 1;
        size_t voicePosEnd = response.find(',', voicePos );

        std::string voiceSubstring = response.substr(voicePosStart ,voicePosEnd  - voicePosStart );

        std::cout << "voice: " << voiceSubstring  << std::endl;
        EXPECT_EQ(voiceSubstring ,"\"carol\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'voice' not found in the response.";
    }
}

/**
 * @name  : SetNullVoice
 * @brief : Set voice as NULL and check whether it return error
 *
 * @param[in]   :  Set NULL voice
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetNullVoice) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"voice\": null}"), response));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));
    size_t voicePos = response.find("\"voice\"");

    if (voicePos  != string::npos) {
        // Find the start and end positions of the ttsendpoint value
        size_t voicePosStart = response.find(':', voicePos ) + 1;
        size_t voicePosEnd = response.find(',', voicePos );

        std::string voiceSubstring = response.substr(voicePosStart ,voicePosEnd  - voicePosStart );

        std::cout << "voice: " << voiceSubstring  << std::endl;
        EXPECT_EQ(voiceSubstring ,"\"carol\"");
     } else {
        EXPECT_TRUE(false) << "Error: 'voice' not found in the response.";
    }
}
/**
 * @name  : SetFallbackTextScenarioEmpty
 * @brief : Set FallbackText scenario Empty
 *
 * @param[in]   :  Set scenario as invalid
 * @expected    :  ERROR_GENERAL
 */

/*TEST_F(TTSInitializedTest, SetFallbackTextScenarioEmpty) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"fallbacktext\": {\"scenario\":\"\",\"value\":\"speak text\"}}"), response));
}*/

/**
 * @name  : SetFallbackTextScenarioWhiteSpace
 * @brief : Set FallbackText scenario " "
 *
 * @param[in]   :  Set scenario as " "
 * @expected    :  ERROR_GENERAL
 */

/*TEST_F(TTSInitializedTest, SetFallbackTextScenarioWhiteSpace) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"fallbacktext\": {\"scenario\":\" \",\"value\":\"speak text\"}}"), response));
}*/

/**
 * @name  : SetFallbackTextScenarioNull
 * @brief : Set FallbackText scenario NULL
 *
 * @param[in]   :  Set scenario as NULL
 * @expected    :  ERROR_GENERAL
 */

/*TEST_F(TTSInitializedTest, SetFallbackTextScenarioNull) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"fallbacktext\": {\"scenario\":NULL,\"value\":\"speak text\"}}"), response));
}*/

/**
 * @name  : SetFallbackTextInvalid
 * @brief : Set FallbackText scenario other than offline
 *
 * @param[in]   :  Set scenario as invalid
 * @expected    :  ERROR_GENERAL
 */

/*TEST_F(TTSInitializedTest, SetFallbackTextScenarioInvalid) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"fallbacktext\": {\"scenario\":\"invalid\",\"value\":\"speak text\"}}"), response));
}*/

/**
 * @name  : SetAuthInfoTypeEmpty
 * @brief : Set AuthInfo type Empty
 *
 * @param[in]   :  Set type as invalid
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetAuthInfoTypeEmpty) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"authinfo\": {\"type\":\"\",\"value\":\"speak text\"}}"), response));
}

/**
 * @name  : SetAuthInfoTypeWhiteSpace
 * @brief : Set AuthInfo type " "
 *
 * @param[in]   :  Set type as " "
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetAuthInfoTypeWhiteSpace) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"authinfo\": {\"type\":\" \",\"value\":\"speak text\"}}"), response));
}

/**
 * @name  : SetAuthInfoTypeNull
 * @brief : Set AuthInfo type NULL
 *
 * @param[in]   :  Set type as NULL
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetAuthInfoTypeNull) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"authinfo\": {\"type\":null,\"value\":\"speak text\"}}"), response));
}

/**
 * @name  : SetAuthInfoInvalid
 * @brief : Set AuthInfo type other than offline
 *
 * @param[in]   :  Set type as invalid
 * @expected    :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetAuthInfoTypeInvalid) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));
    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("setttsconfiguration"), _T("{\"authinfo\": {\"type\":\"invalid\",\"value\":\"xxxxyyyyy\"}}"), response));
}
/*******************************************************************************************************************
 * Test function for SetACL
 * resume          :
 *                Gives speak access for applications
 *
 *                @return Response object contains bool success 
 * Use case coverage:
 *                @Success :
 *                @Failure :
 ********************************************************************************************************************/
/**
 * @name  : SetACLInvalidMethod
 * @brief : Calling speak method with  invalid method other than speak
 *
 * @param[in]   :  method of tts and app name
 * @return      :  ERROR_NONE
 */

TEST_F(TTSInitializedTest, SetACLInvalidMethod) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":\"invalid\",\"apps\":\"WebAPP1\"}]}"),
        response
    ));
}

/**
 * @name  : SetACLEmptyMethod
 * @brief : Calling speak method with empty method
 *
 * @param[in]   :  method of tts and app name
 * @return      :  ERROR_NONE
 */

TEST_F(TTSInitializedTest, SetACLEmptyMethod) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":\"\",\"apps\":\"WebAPP1\"}]}"),
        response
    ));
}
/**
 * @name  : SetACLWhiteSpaceMethod
 * @brief : Calling speak method with empty method
 *
 * @param[in]   :  method of tts and app name
 * @return      :  ERROR_NONE
 */

TEST_F(TTSInitializedTest, SetACLWhitespaceMethod) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":\" \",\"apps\":\"WebAPP1\"}]}"),
        response
    ));
}
/**
 * @name  : SetACLNullMethod
 * @brief : Calling speak method with empty method
 *
 * @param[in]   :  method of tts and app name
 * @return      :  ERROR_NONE
 */

TEST_F(TTSInitializedTest, SetACLNullMethod) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":NULL,\"apps\":\"WebAPP1\"}]}"),
        response
    ));
}

/***
 * @name  : SetACLEmptyApp
 * @brief : Calling speak method with empty method
 *
 * @param[in]   :  method of tts and app name
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetACLEmptyApp) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":\"speak\",\"apps\":\"\"}]}"),
        response
    ));
}
/**
 * @name  : SetACLWhiteSpaceApp
 * @brief : Calling speak method with empty method
 *
 * @param[in]   :  method of tts and app name
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetACLWhitespaceApp) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":\"speak\",\"apps\":\" \"}]}"),
        response
    ));
}
/**
 * @name  : SetACLNullApp
 * @brief : Calling speak method with empty method
 *
 * @param[in]   :  method of tts and app name
 * @return      :  ERROR_GENERAL
 */

TEST_F(TTSInitializedTest, SetACLNullApp) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":\"speak\",\"apps\":NULL}]}"),
        response
    ));
}
TEST_F(TTSInitializedTest, Test_SetACL_Failure) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(
        connection,
        _T("setACL"),
        _T("{\"accesslist\": [{\"method\":\"speak\",\"apps\":\"WebAPP1\"}]}"),
        response
    ));

    EXPECT_EQ(response, _T("{\"success\":true}"));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(
        connection,
        _T("setttsconfiguration"),
        _T("{\"language\": \"en-US\",\"voice\": \"carol\","
            "\"ttsendpoint\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\","
            "\"ttsendpointsecured\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\"}"
        ),
        response
    ));

    EXPECT_EQ(Core::ERROR_GENERAL, handler.Invoke(
        connection,
        _T("speak"),
        _T("{\"text\": \"speech_123\",\"callsign\":\"WebAPP2\"}"),
        response
    ));

    EXPECT_EQ(response, _T(""));
}

/**
 * @name  : UpdateSetTTSConfiguration
 * @brief : Update the value and check the value using gettsconfiguration
 *
 * @param[in]   :  Valid configuration
 * @expected    :  getttsconfiguration should return the update value
 */

TEST_F(TTSInitializedTest, UpdateSetTTSConfiguration) {
    EXPECT_EQ(string(""), plugin->Initialize(&service));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(
        connection,
        _T("setttsconfiguration"),
        _T("{\"language\": \"en-US\",\"voice\": \"carol\","
            "\"ttsendpoint\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\","
            "\"ttsendpointsecured\":\"http://cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net/tts/v1/cdn/location?\","
            "\"volume\": \"95\",\"primvolduckpercent\": \"50\",\"rate\": \"40\",\"speechrate\":\"medium\"}"
        ),
        response
    ));

    EXPECT_EQ(Core::ERROR_NONE, handler.Invoke(connection, _T("getttsconfiguration"), _T(""), response));

    EXPECT_EQ(response,
        _T("{\"ttsendpoint\":\"http:\\/\\/cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net\\/tts\\/v1\\/cdn\\/location?\","
            "\"ttsendpointsecured\":\"http:\\/\\/cdn-ec-ric-312.voice-guidance-tts.xcr.comcast.net\\/tts\\/v1\\/cdn\\/location?\","
            "\"language\":\"en-US\",\"voice\":\"carol\",\"speechrate\":\"medium\",\"rate\":40,\"volume\":\"95\","
            "\"TTS_Status\":0,\"success\":true}"
        ));
}

