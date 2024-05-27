/**
* If not stated otherwise in this file or this component's LICENSE
* file the following copyright and licenses apply:
*
* Copyright 2022 RDK Management
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

#pragma once


#include "Module.h"
#include <iostream>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

using namespace std;

//#include <interfaces/INetworkManager.h>
#include "INetworkManager.h"
#include "NetworkManagerLogger.h"
#include "WifiSignalStrengthMonitor.h"
#include "NetworkManagerConnectivity.h"
#include "StunClient.h"

#define LOG_ENTRY_FUNCTION() { NMLOG_TRACE("Entering=%s", __FUNCTION__ ); }

namespace WPEFramework
{
    namespace Plugin
    {
        class NetworkManagerImplementation : public Exchange::INetworkManager
        {
        enum NetworkEvents {
                NETMGR_PING,
                NETMGR_TRACE,
            };

        class Config : public Core::JSON::Container {
        private:
            Config(const Config&);
            Config& operator=(const Config&);

        public:
            class ConnectivityConf : public Core::JSON::Container {
            public:
                ConnectivityConf& operator=(const ConnectivityConf&) = delete;

                ConnectivityConf()
                    : Core::JSON::Container()
                    , captiveEnpt1(_T("http://clients3.google.com/generate_204"))
                    , connMonitorEnpt1(_T("google.com"))
                    , connMonitorTimeOut(60)
                {
                    Add(_T("captiveEnpt1"), &captiveEnpt1);
                    Add(_T("captiveEnpt2"), &captiveEnpt2);
                    Add(_T("captiveEnpt3"), &captiveEnpt3);
                    Add(_T("connMonitorEnpt1"), &connMonitorEnpt1);
                    Add(_T("connMonitorEnpt2"), &connMonitorEnpt2);
                    Add(_T("connMonitorEnpt3"), &connMonitorEnpt3);
                    Add(_T("connMonitorEnpt4"), &connMonitorEnpt4);
                    Add(_T("connMonitorEnpt5"), &connMonitorEnpt5);
                    Add(_T("connMonitorinterval"), &connMonitorTimeOut);
                }
                ~ConnectivityConf() override = default;

            public:
                /* connectivity configuration */
                /* captive monitor endpoints */
                Core::JSON::String captiveEnpt1;
                Core::JSON::String captiveEnpt2;
                Core::JSON::String captiveEnpt3;
                /* connectivity monitor endpoint */
                Core::JSON::String connMonitorEnpt1;
                Core::JSON::String connMonitorEnpt2;
                Core::JSON::String connMonitorEnpt3;
                Core::JSON::String connMonitorEnpt4;
                Core::JSON::String connMonitorEnpt5;
                Core::JSON::DecUInt32 connMonitorTimeOut;
            };

            class StunConf : public Core::JSON::Container {
                public:
                    StunConf& operator=(const StunConf&) = delete;

                    StunConf()
                        : Core::JSON::Container()
                        , stunEndpoint(_T("stun.l.google.com"))
                        , port(19302)
                        , interval(30)
                    {
                        Add(_T("endpoint"), &stunEndpoint);
                        Add(_T("port"), &port);
                        Add(_T("interval"), &interval);
                    }
                    ~StunConf() override = default;

                public:
                    /* stun configuration */
                    Core::JSON::String stunEndpoint;
                    Core::JSON::DecUInt32 port;
                    Core::JSON::DecUInt32 interval;
            };

        public:
            Config()
                : Core::JSON::Container()
                {
                    Add(_T("connectivity"), &connectivityConf);
                    Add(_T("stun"), &stunConf);
                    Add(_T("loglevel"), &loglevel);
                }
            ~Config() override = default;

        public:
            ConnectivityConf connectivityConf;
            StunConf stunConf;
            Core::JSON::DecUInt32 loglevel;
        };

        public:
            NetworkManagerImplementation();
            ~NetworkManagerImplementation() override;

            // Do not allow copy/move constructors
            NetworkManagerImplementation(const NetworkManagerImplementation &) = delete;
            NetworkManagerImplementation &operator=(const NetworkManagerImplementation &) = delete;

            BEGIN_INTERFACE_MAP(NetworkManagerImplementation)
            INTERFACE_ENTRY(Exchange::INetworkManager)
            END_INTERFACE_MAP

            // Handle Notification registration/removal
            uint32_t Register(INetworkManager::INotification *notification) override;
            uint32_t Unregister(INetworkManager::INotification *notification) override;

        public:
            // Below Control APIs will work with RDK or GNome NW.
            /* @brief Get all the Available Interfaces */
            uint32_t GetAvailableInterfaces (IInterfaceDetailsIterator*& interfaces/* @out */) override;

            /* @brief Get the active Interface used for external world communication */
            uint32_t GetPrimaryInterface (string& interface /* @out */) override;
            /* @brief Set the active Interface used for external world communication */
            uint32_t SetPrimaryInterface (const string& interface/* @in */) override;

            uint32_t EnableInterface (const string& interface/* @in */) override;
            uint32_t DisableInterface (const string& interface/* @in */) override;
            /* @brief Get IP Address Of the Interface */
            uint32_t GetIPSettings(const string& interface /* @in */, const string &ipversion /* @in */, IPAddressInfo& result /* @out */) override;
            /* @brief Set IP Address Of the Interface */
            uint32_t SetIPSettings(const string& interface /* @in */, const string &ipversion /* @in */, const IPAddressInfo& address /* @in */) override;

            // WiFi Specific Methods
            /* @brief Initiate a WIFI Scan; This is Async method and returns the scan results as Event */
            uint32_t StartWiFiScan(const WiFiFrequency frequency /* @in */);
            uint32_t StopWiFiScan(void) override;

            uint32_t GetKnownSSIDs(IStringIterator*& ssids /* @out */) override;
            uint32_t AddToKnownSSIDs(const WiFiConnectTo& ssid /* @in */) override;
            uint32_t RemoveKnownSSID(const string& ssid /* @in */) override;

            uint32_t WiFiConnect(const WiFiConnectTo& ssid /* @in */) override;
            uint32_t WiFiDisconnect(void) override;
            uint32_t GetConnectedSSID(WiFiSSIDInfo&  ssidInfo /* @out */) override;

            uint32_t StartWPS(const WiFiWPS& method /* @in */, const string& wps_pin /* @in */) override;
            uint32_t StopWPS(void) override;
            uint32_t GetWifiState(WiFiState &state) override;
            uint32_t GetWiFiSignalStrength(string& ssid /* @out */, string& signalStrength /* @out */, WiFiSignalQuality& quality /* @out */) override;

            uint32_t SetStunEndpoint (string const endPoint /* @in */, const uint32_t port /* @in */, const uint32_t bindTimeout /* @in */, const uint32_t cacheTimeout /* @in */) override;
            uint32_t GetStunEndpoint (string &endPoint /* @out */, uint32_t& port /* @out */, uint32_t& bindTimeout /* @out */, uint32_t& cacheTimeout /* @out */) const override;

            /* @brief Get ConnectivityTest Endpoints */
            uint32_t GetConnectivityTestEndpoints(IStringIterator*& endPoints/* @out */) const override;
            /* @brief Set ConnectivityTest Endpoints */
            uint32_t SetConnectivityTestEndpoints(IStringIterator* const endPoints /* @in */) override;

            /* @brief Get Internet Connectivty Status */ 
            uint32_t IsConnectedToInternet(const string &ipversion /* @in */, InternetStatus &result /* @out */) override;
            /* @brief Get Authentication URL if the device is behind Captive Portal */ 
            uint32_t GetCaptivePortalURI(string &endPoints/* @out */) const override;

            /* @brief Start The Internet Connectivity Monitoring */ 
            uint32_t StartConnectivityMonitoring(const uint32_t interval/* @in */) override;
            /* @brief Stop The Internet Connectivity Monitoring */ 
            uint32_t StopConnectivityMonitoring(void) const override;

            /* @brief Get the Public IP used for external world communication */
            uint32_t GetPublicIP (const string &ipversion /* @in */,  string& ipAddress /* @out */) override;

            /* @brief Request for ping and get the response in as event. The GUID used in the request will be returned in the event. */
            uint32_t Ping (const string ipversion /* @in */,  const string endpoint /* @in */, const uint32_t noOfRequest /* @in */, const uint16_t timeOutInSeconds /* @in */, const string guid /* @in */, string& response /* @out */) override;

            /* @brief Request for trace get the response in as event. The GUID used in the request will be returned in the event. */
            uint32_t Trace (const string ipversion /* @in */,  const string endpoint /* @in */, const uint32_t noOfRequest /* @in */, const string guid /* @in */, string& response /* @out */) override;

            uint32_t GetSupportedSecurityModes(ISecurityModeIterator*& securityModes /* @out */) const override;

            /* @brief Set the network manager plugin log level */
            uint32_t SetLogLevel(const NMLogging& logLevel /* @in */) override;

            /* @brief configure network manager plugin */
            uint32_t Configure(const string& configLine /* @in */, NMLogging& logLevel /* @out */) override;

            /* Events */
            void ReportInterfaceStateChangedEvent(INetworkManager::InterfaceState state, string interface);
            void ReportIPAddressChangedEvent(const string& interface, bool isAcquired, bool isIPv6, const string& ipAddress);
            void ReportActiveInterfaceChangedEvent(const string prevActiveInterface, const string currentActiveinterface);
            void ReportInternetStatusChangedEvent(const InternetStatus oldState, const InternetStatus newstate);
            void ReportAvailableSSIDsEvent(const string jsonOfWiFiScanResults);
            void ReportWiFiStateChangedEvent(const INetworkManager::WiFiState state);
            void ReportWiFiSignalStrengthChangedEvent(const string ssid , const string signalLevel , const WiFiSignalQuality signalQuality);

        private:
            void platform_init();
            void executeExternally(NetworkEvents event, const string commandToExecute, string& response);

        private:
            std::list<Exchange::INetworkManager::INotification *> _notificationCallbacks;
            Core::CriticalSection _notificationLock;
            string m_defaultInterface;
            string m_publicIP;
            stun::client stunClient;
            string m_stunEndPoint;
            uint16_t m_stunPort;
            uint16_t m_stunBindTimeout;
            uint16_t m_stunCacheTimeout;
        public:
            WifiSignalStrengthMonitor wifiSignalStrengthMonitor;
            mutable ConnectivityMonitor connectivityMonitor;
        };
    }
}
