/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
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
 */

#include "DisplayInfo.h"
#include <string>

namespace WPEFramework {
namespace Plugin {

    SERVICE_REGISTRATION(DisplayInfo, 1, 0);

    static Core::ProxyPoolType<Web::Response> responseFactory(4);
    static Core::ProxyPoolType<Web::JSONBodyType<JsonData::DisplayInfo::DisplayinfoData>> jsonResponseFactory(4);

    /* virtual */ const string DisplayInfo::Initialize(PluginHost::IShell* service)
    {
        ASSERT(service != nullptr);
        ASSERT(_connectionProperties == nullptr);

        string message;
        Config config;

        config.FromString(service->ConfigLine());
        _skipURL = static_cast<uint8_t>(service->WebPrefix().length());

        _connectionProperties = service->Root<Exchange::IConnectionProperties>(_connectionId, 2000, _T("DisplayInfoImplementation"));
        if (_connectionProperties != nullptr) {

            _graphicsProperties = _connectionProperties->QueryInterface<Exchange::IGraphicsProperties>();
            if (_graphicsProperties == nullptr) {

                _connectionProperties->Release();
                _connectionProperties = nullptr;
            } else {
                _notification.Initialize(_connectionProperties);
                _displayProperties = _connectionProperties->QueryInterface<Exchange::IDisplayProperties>();
                if (_displayProperties) _notification.Initialize(_displayProperties);
            }
        }

        if (_connectionProperties == nullptr) {
            message = _T("DisplayInfo could not be instantiated.");
        }

        return message;
    }

    /* virtual */ void DisplayInfo::Deinitialize(PluginHost::IShell* service)
    {
        ASSERT(_connectionProperties != nullptr);

        _notification.Deinitialize();

        ASSERT(_graphicsProperties != nullptr);
        if (_graphicsProperties != nullptr) {
            _graphicsProperties->Release();
            _graphicsProperties = nullptr;
        }

        ASSERT(_connectionProperties != nullptr);
        if (_connectionProperties != nullptr) {
            _connectionProperties->Release();
            _connectionProperties = nullptr;
        }

        if (_displayProperties != nullptr)
        {
            _displayProperties->Release();
            _displayProperties = nullptr;
        }

        _connectionId = 0;
    }

    /* virtual */ string DisplayInfo::Information() const
    {
        // No additional info to report.
        return (string());
    }

    /* virtual */ void DisplayInfo::Inbound(Web::Request& /* request */)
    {
    }

    /* virtual */ Core::ProxyType<Web::Response> DisplayInfo::Process(const Web::Request& request)
    {
        ASSERT(_skipURL <= request.Path.length());

        Core::ProxyType<Web::Response> result(PluginHost::IFactories::Instance().Response());

        // By default, we assume everything works..
        result->ErrorCode = Web::STATUS_OK;
        result->Message = "OK";

        // <GET> - currently, only the GET command is supported, returning system info
        if (request.Verb == Web::Request::HTTP_GET) {

            Core::ProxyType<Web::JSONBodyType<JsonData::DisplayInfo::DisplayinfoData>> response(jsonResponseFactory.Element());

            Core::TextSegmentIterator index(Core::TextFragment(request.Path, _skipURL, static_cast<uint32_t>(request.Path.length()) - _skipURL), false, '/');

            // Always skip the first one, it is an empty part because we start with a '/' if there are more parameters.
            index.Next();

            Info(*response);
            result->ContentType = Web::MIMETypes::MIME_JSON;
            result->Body(Core::proxy_cast<Web::IBody>(response));
        } else {
            result->ErrorCode = Web::STATUS_BAD_REQUEST;
            result->Message = _T("Unsupported request for the [DisplayInfo] service.");
        }

        return result;
    }

    void DisplayInfo::Info(JsonData::DisplayInfo::DisplayinfoData& displayInfo) const
    {
        displayInfo.Totalgpuram = _graphicsProperties->TotalGpuRam();
        displayInfo.Freegpuram = _graphicsProperties->FreeGpuRam();

        displayInfo.Audiopassthrough = _connectionProperties->IsAudioPassthrough();
        displayInfo.Connected = _connectionProperties->Connected();
        displayInfo.Width = _connectionProperties->Width();
        displayInfo.Height = _connectionProperties->Height();
        displayInfo.Hdcpmajor = _connectionProperties->HDCPMajor();
        displayInfo.Hdcpminor = _connectionProperties->HDCPMinor();
        displayInfo.Hdrtype = static_cast<JsonData::DisplayInfo::DisplayinfoData::HdrtypeType>(_connectionProperties->Type());
    }

    void DisplayInfo::getCurrentResolution(JsonData::DisplayInfo::VideoPlaybackResolutionData& playbackResolution) const
    {
        playbackResolution.VideoPlaybackResolution = _displayProperties->getCurrentResolution();
    }

    void DisplayInfo::getConnectedVideoDisplay(JsonData::DisplayInfo::VideoOutputPortNameData& connectedDisplay) const
    {
        connectedDisplay.VideoOutputPortName = _displayProperties->getConnectedVideoDisplay();
    }

    void DisplayInfo::getTVHDRCapabilities(JsonData::DisplayInfo::TvHdrCapabilitesData& TvHdrCaps) const
    {
        string hdrCaps("");
        int capabilities = 0;
        _displayProperties->getTvHdrCapabilities(hdrCaps, capabilities);
        string delim = ",";
        size_t pos = 0;
        string token;
        while ((pos = hdrCaps.find(delim)) != string::npos)
        {
            Core::JSON::String hdrCap;
            token = hdrCaps.substr(0, pos);
            hdrCap.FromString(_T(token));
            TvHdrCaps.TvHdrCapabilites.Add(hdrCap);
            hdrCaps.erase(0, pos + delim.length());
        }
        TvHdrCaps.Capabilities = capabilities;
    }

    void DisplayInfo::getSettopHDRSupport(JsonData::DisplayInfo::StbHdrCapabilitiesData& StbHdrCaps) const
    {
        string hdrCaps("");
        int capabilities = 0;
        _displayProperties->getStbHdrCapabilities(hdrCaps, capabilities);
        string delim = ",";
        size_t pos = 0;
        string token;
        while ((pos = hdrCaps.find(delim)) != string::npos)
        {
            Core::JSON::String hdrCap;
            token = hdrCaps.substr(0, pos);
            hdrCap.FromString(_T(token));
            StbHdrCaps.StbHdrCapabilities.Add(hdrCap);
            hdrCaps.erase(0, pos + delim.length());
        }
        StbHdrCaps.Capabilities = capabilities;
    }

    void DisplayInfo::IsOutputHDR(JsonData::DisplayInfo::OutputHdrStatusData& OutputHdr) const
    {
        OutputHdr.IsOutputHDR = _displayProperties->isOutputHDR();
    }

    void DisplayInfo::getHdmiPreferences(JsonData::DisplayInfo::HdmiPreferencesData& HdmiPref) const
    {
        int hdcpversion = _displayProperties->getHdmiPreferences();
        if(hdcpversion) HdmiPref.CurrentHdcpProtocol = hdcpversion;
    }

    void DisplayInfo::setHdmiPreferences(const JsonData::DisplayInfo::HdmiPreferencesData& HdmiPref)
    {
        _displayProperties->setHdmiPreferences(HdmiPref.CurrentHdcpProtocol.Value());
    }

    void DisplayInfo::isAudioEquivalenceEnabled(JsonData::DisplayInfo::AudioEquivalenceStatusData& AudioEq) const
    {
        AudioEq.IsAudioEquivalenceEnabled = _displayProperties->isAudioEquivalenceEnabled();
    }

    void DisplayInfo::readEDID(JsonData::DisplayInfo::EDIDData& EDIDData) const
    {
        EDIDData.EdidData = _displayProperties->readEDID();
    }


} // namespace Plugin
} // namespace WPEFramework
