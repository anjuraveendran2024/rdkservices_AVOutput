/**
* If not stated otherwise in this file or this component's LICENSE
* file the following copyright and licenses apply:
*
* Copyright 2020 RDK Management
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
**/

#include "utils.h"
#include "libIBus.h"
#include "WifiManagerWPS.h"
#include "wifiSrvMgrIarmIf.h"

namespace WPEFramework
{
    namespace Plugin
    {
        WifiManagerWPS::WifiManagerWPS()
        {
        }

        WifiManagerWPS::~WifiManagerWPS()
        {
        }

        uint32_t WifiManagerWPS::initiateWPSPairing(const JsonObject &parameters, JsonObject &response)
        {
            LOGINFOMETHOD();
            IARM_Bus_WiFiSrvMgr_Param_t param;
            memset(&param, 0, sizeof(param));

            IARM_Result_t retVal = IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME, IARM_BUS_WIFI_MGR_API_initiateWPSPairing, (void *)&param, sizeof(param));
            LOGINFO("[%s] : retVal:%d status:%d", IARM_BUS_WIFI_MGR_API_initiateWPSPairing, retVal, param.status);

            response["result"] = string();
            returnResponse(retVal == IARM_RESULT_SUCCESS);
        }

        uint32_t WifiManagerWPS::cancelWPSPairing(const JsonObject &parameters, JsonObject &response)
        {
            LOGINFOMETHOD();
            IARM_Bus_WiFiSrvMgr_Param_t param;
            memset(&param, 0, sizeof(param));

            IARM_Result_t retVal = IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME, IARM_BUS_WIFI_MGR_API_cancelWPSPairing, (void *)&param, sizeof(param));
            LOGINFO("[%s] : retVal:%d status:%d", IARM_BUS_WIFI_MGR_API_cancelWPSPairing, retVal, param.status);

            response["result"] = string();
            returnResponse(retVal == IARM_RESULT_SUCCESS);
        }

        uint32_t WifiManagerWPS::saveSSID(const JsonObject &parameters, JsonObject &response)
        {
            LOGINFOMETHOD();

            returnIfStringParamNotFound(parameters, "ssid");
            returnIfStringParamNotFound(parameters, "passphrase");
            returnIfNumberParamNotFound(parameters, "securityMode");

            bool saved = false;
            IARM_Bus_WiFiSrvMgr_Param_t param;
            memset(&param, 0, sizeof(param));

            strncpy(param.data.connect.ssid, parameters["ssid"].String().c_str(), SSID_SIZE - 1);
            strncpy(param.data.connect.passphrase, parameters["passphrase"].String().c_str(), PASSPHRASE_BUFF - 1);
            param.data.connect.security_mode = static_cast<SsidSecurity>(parameters["securityMode"].Number());

            IARM_Result_t retVal = IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME, IARM_BUS_WIFI_MGR_API_saveSSID, (void *)&param, sizeof(param));
            saved = (retVal == IARM_RESULT_SUCCESS) && param.status;
            LOGINFO("[%s] : retVal:%d status:%d", IARM_BUS_WIFI_MGR_API_saveSSID, retVal, param.status);

            response["result"] = (saved ? 0 : 1);
            returnResponse(true);
        }

        uint32_t WifiManagerWPS::clearSSID(const JsonObject &parameters, JsonObject &response)
        {
            LOGINFOMETHOD();
            bool cleared = false;

            IARM_Bus_WiFiSrvMgr_Param_t param;
            memset(&param, 0, sizeof(param));

            IARM_Result_t retVal = IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME, IARM_BUS_WIFI_MGR_API_clearSSID, (void *)&param, sizeof(param));
            cleared = (retVal == IARM_RESULT_SUCCESS) && param.status;
            LOGINFO("[%s] : retVal:%d status:%d", IARM_BUS_WIFI_MGR_API_clearSSID, retVal, param.status);

            response["result"] = (cleared ? 0 : 1);
            returnResponse(true);
        }

        uint32_t WifiManagerWPS::getPairedSSID(const JsonObject &parameters, JsonObject &response) const
        {
            LOGINFOMETHOD();
            IARM_Bus_WiFiSrvMgr_Param_t param;
            memset(&param, 0, sizeof(param));

            IARM_Result_t retVal = IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME, IARM_BUS_WIFI_MGR_API_getPairedSSID, (void *)&param, sizeof(param));
            if (retVal == IARM_RESULT_SUCCESS)
            {
                response["ssid"] = string(param.data.getPairedSSID.ssid, SSID_SIZE);
            }
            LOGINFO("[%s] : retVal:%d", IARM_BUS_WIFI_MGR_API_getPairedSSID, retVal);

            returnResponse(retVal == IARM_RESULT_SUCCESS);
        }

        uint32_t WifiManagerWPS::getPairedSSIDInfo(const JsonObject &parameters, JsonObject &response) const
        {
            LOGINFOMETHOD();
            IARM_Bus_WiFiSrvMgr_Param_t param;
            memset(&param, 0, sizeof(param));

            IARM_Result_t retVal = IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME, IARM_BUS_WIFI_MGR_API_getPairedSSIDInfo, (void *)&param, sizeof(param));
            if (retVal == IARM_RESULT_SUCCESS)
            {
                response["ssid"] = string(param.data.getPairedSSIDInfo.ssid, SSID_SIZE);
                response["bssid"] = string(param.data.getPairedSSIDInfo.bssid, BSSID_BUFF);
            }
            LOGINFO("[%s] : retVal:%d", IARM_BUS_WIFI_MGR_API_getPairedSSIDInfo, retVal);

            returnResponse(retVal == IARM_RESULT_SUCCESS);
        }

        uint32_t WifiManagerWPS::isPaired(const JsonObject &parameters, JsonObject &response) const
        {
            LOGINFOMETHOD();
            bool paired = false;

            IARM_Bus_WiFiSrvMgr_Param_t param;
            memset(&param, 0, sizeof(param));

            IARM_Result_t retVal = IARM_Bus_Call(IARM_BUS_NM_SRV_MGR_NAME, IARM_BUS_WIFI_MGR_API_isPaired, (void *)&param, sizeof(param));
            paired = (retVal == IARM_RESULT_SUCCESS) && param.data.isPaired;
            LOGINFO("[%s] : retVal:%d paired:%d", IARM_BUS_WIFI_MGR_API_isPaired, retVal, param.data.isPaired);

            response["result"] = (paired ? 0 : 1);
            returnResponse(true);
        }
    } // namespace Plugin
} // namespace WPEFramework
