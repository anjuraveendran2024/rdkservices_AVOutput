#include <string>
#include <list>
#include <memory>
#include <iostream>
#include "rtConnection.h"
#include "rtMessage.h"

#include "IOTConnector.h"
#define RBUS_COMPONENT_NAME "IOTControlPlugin"
#define RBUS_METHOD_GETDEVICES "GetIoTDevices"
#define RBUS_METHOD_GETDEVICEPROPERTIES "GetDeviceProperties"
#define RBUS_METHOD_GETDEVICEPROPERTY "GetDeviceProperty"
#define RBUS_METHOD_SENDCOMMAND "SendCommand"

#define RTMESSAGE_TIMEOUT_MILLIS 2000
namespace WPEFramework
{
    namespace iotbridge
    {

        rtConnection con;
        rtError rtConnStatus = RT_NO_CONNECTION;

        bool initializeIPC(const std::string &remoteAddr)
        {
            if (rtConnection_Create(&con, "RIoT", remoteAddr.c_str()) == RT_OK)
                rtConnStatus = RT_OK;
            return rtConnStatus == RT_OK;
        }

        void unInitialize()
        {
            if (RT_OK == rtConnStatus)
                rtConnection_Destroy(con);
            rtConnStatus = RT_NO_CONNECTION;
        }
        int getDeviceList(std::list<std::shared_ptr<IOTDevice> > &deviceList)
        {
            int count = -1;

            if (RT_OK != rtConnStatus)
                return count;

            rtError err;
            rtMessage res;
            rtMessage req;
            rtMessage_Create(&req);
            err = rtConnection_SendRequest(con, req, RBUS_METHOD_GETDEVICES, &res, RTMESSAGE_TIMEOUT_MILLIS);
            std::cout << "RPC returns " << rtStrError(err) << std::endl;
            if (RT_OK == err)
            {

                rtMessage devices;
                char *entry;

                rtMessage_GetArrayLength(devices, "devices", &count);
                std::shared_ptr<IOTDevice> device(new IOTDevice());

                rtMessage_GetMessage(res, "devices", &devices);

                for (int i = 0; i < count; i++)
                {
                    rtMessage devEntry;
                    rtMessage_GetMessageItem(res, "devices", count, &devEntry);

                    rtMessage_GetString(devEntry, "name", (const char **)&entry);
                    device->deviceName = entry;
                    free(entry);

                    rtMessage_GetString(devEntry, "uuid", (const char **)&entry);
                    device->deviceId = entry;
                    free(entry);

                    rtMessage_GetString(devEntry, "devType", (const char **)&entry);
                    int x = std::stoi(entry);
                    device->devType = x == 0 ? CAMERA : LIGHT_BULB;
                    free(entry);

                    deviceList.push_back(device);
                }
            }
            rtMessage_Release(req);
            rtMessage_Release(res);

            return count;
        }
        int getDeviceProperties(std::shared_ptr<IOTDevice> iotDevice, std::list<std::string> &propList)
        {
            int count = -1;

            if (RT_OK != rtConnStatus)
                return count;
            rtError err;
            rtMessage res,req;
            rtMessage_Create(&req);
            rtMessage_SetString(req, "deviceId", iotDevice->deviceId.c_str());
            err = rtConnection_SendRequest(con, req, RBUS_METHOD_GETDEVICEPROPERTIES, &res, RTMESSAGE_TIMEOUT_MILLIS);
            std::cout << "RPC returns " << rtStrError(err) << std::endl;
            if (RT_OK == err)
            {

                rtMessage properties;
                rtMessage_GetArrayLength(res, "properties", &count);
                rtMessage_GetMessage(res, "properties", &properties);

                for (int i = 0; i < count; i++)
                {
                    char *entry;
                    rtMessage_GetStringItem(res, "devices", count, (const char **)&entry);
                    propList.push_back(entry);
                }
            }
            rtMessage_Release(req);
            rtMessage_Release(res);
            return count;
        }
        std::string getDeviceProperty(std::shared_ptr<IOTDevice> iotDevice, const std::string &propertyName)
        {
            std::string value;

            if (RT_OK != rtConnStatus)
                return "";

            rtError err;
            rtMessage res;
            rtMessage req;

            rtMessage_Create(&req);
            rtMessage_SetString(req, "deviceId", iotDevice->deviceId.c_str());
            rtMessage_SetString(req, "property", propertyName.c_str());
            err = rtConnection_SendRequest(con, req, RBUS_METHOD_GETDEVICEPROPERTY, &res, RTMESSAGE_TIMEOUT_MILLIS);
            std::cout << "RPC returns " << rtStrError(err) << std::endl;

            if (RT_OK == err)
            {
                char *entry;
                rtMessage_GetString(res, "value", (const char **)&entry);
                value = entry;
            }

            rtMessage_Release(req);
            rtMessage_Release(res);
            return value;
        }

    } // namespace iotbridge
} // namespace wpeframework