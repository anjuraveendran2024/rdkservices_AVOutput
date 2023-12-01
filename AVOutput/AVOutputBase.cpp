/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2022 Sky UK
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
*/

#include <string>
#include "AVOutputBase.h"
#include "UtilsIarm.h"

const char* PLUGIN_IARM_BUS_NAME = "Thunder_Plugins";

namespace WPEFramework {
namespace Plugin {

    AVOutputBase::AVOutputBase()
               : _skipURL(0)
    {
        LOGINFO("Entry\n");
        //Common API Registration
        LOGINFO("Exit \n");
    }

    AVOutputBase::~AVOutputBase()
    {
        LOGINFO();
    }

    void AVOutputBase::Initialize()
    {
	LOGINFO("Entry\n");
	LOGINFO("Exit\n");
        
    }

    void AVOutputBase::Deinitialize()
    {
	LOGINFO("Entry\n");
	LOGINFO("Exit\n");

    }

    void AVOutputBase::InitializeIARM()
    {
#if !defined (HDMIIN_4K_ZOOM)
        if (IARMinit())
        {
            IARM_Result_t res;
            IARM_CHECK( IARM_Bus_RegisterEventHandler(IARM_BUS_DSMGR_NAME,IARM_BUS_DSMGR_EVENT_HDMI_IN_STATUS, dsHdmiStatusEventHandler) );
            IARM_CHECK( IARM_Bus_RegisterEventHandler(IARM_BUS_DSMGR_NAME,IARM_BUS_DSMGR_EVENT_HDMI_IN_VIDEO_MODE_UPDATE, dsHdmiVideoModeEventHandler) );
            IARM_CHECK( IARM_Bus_RegisterEventHandler(IARM_BUS_DSMGR_NAME,IARM_BUS_DSMGR_EVENT_HDMI_IN_HOTPLUG, dsHdmiEventHandler) );
        }
#endif
    }

    void AVOutputBase::DeinitializeIARM()
    {
#if !defined (HDMIIN_4K_ZOOM)
        if (isIARMConnected())
        {
            IARM_Result_t res;
            IARM_CHECK( IARM_Bus_RemoveEventHandler(IARM_BUS_DSMGR_NAME,IARM_BUS_DSMGR_EVENT_HDMI_IN_STATUS, dsHdmiStatusEventHandler) );
            IARM_CHECK( IARM_Bus_RemoveEventHandler(IARM_BUS_DSMGR_NAME,IARM_BUS_DSMGR_EVENT_HDMI_IN_VIDEO_MODE_UPDATE, dsHdmiVideoModeEventHandler) );
            IARM_CHECK( IARM_Bus_RemoveEventHandler(IARM_BUS_DSMGR_NAME,IARM_BUS_DSMGR_EVENT_HDMI_IN_HOTPLUG, dsHdmiEventHandler) );
        }
#endif
    }

    bool AVOutputBase::IARMinit() {
        IARM_Result_t res;
        bool result = false;

        if ( Utils::IARM::isConnected() ) {
            LOGINFO("AVOutputPlugin: IARM already connected");
            result = true;
        } else {
            result = Utils::IARM::init();
            LOGINFO("AVOutputPlugin: IARM_Bus_Init: %d", result);
            if ( result /* already inited or connected */) {

                res = IARM_Bus_Connect();
                LOGINFO("AVOutputPlugin: IARM_Bus_Connect: %d", res);
                if (res == IARM_RESULT_SUCCESS ||
                    res == IARM_RESULT_INVALID_STATE /* already connected or not inited */) {

                    result = Utils::IARM::isConnected();
                } else {
                    LOGERR("AVOutputPlugin: IARM_Bus_Connect failure: %d", res);
                }
            } else {
                LOGERR("AVOutputPlugin: IARM_Bus_Init failure");
            }
        }

        return result;
    }

    bool AVOutputBase::isIARMConnected() 
    {
        IARM_Result_t res;
        int isRegistered = 0;
        res = IARM_Bus_IsConnected(PLUGIN_IARM_BUS_NAME, &isRegistered);
        LOGINFO("AVOutputPlugin: IARM_Bus_IsConnected: %d (%d)", res, isRegistered);

        return (isRegistered == 1);
    }

    void AVOutputBase::dsHdmiEventHandler(const char *owner, IARM_EventId_t eventId, void *data, size_t len)
    {
        LOGINFO("Entry %s\n",__FUNCTION__);
        LOGINFO("Exit %s\n",__FUNCTION__);
    }

    void AVOutputBase::dsHdmiStatusEventHandler(const char *owner, IARM_EventId_t eventId, void *data, size_t len)
    {
        LOGINFO("Entry %s\n",__FUNCTION__);
        LOGINFO("Exit %s\n",__FUNCTION__);
    }

    void AVOutputBase::dsHdmiVideoModeEventHandler(const char *owner, IARM_EventId_t eventId, void *data, size_t len)
    {
        LOGINFO("Entry %s\n",__FUNCTION__);
        LOGINFO("Exit %s\n",__FUNCTION__);
    }

} //namespace WPEFramework

} //namespace Plugin