#include <gtest/gtest.h>

#include "UsbAccess.h"

#include "UdevMock.h"
#include "WrapsMock.h"

using namespace WPEFramework;

class UsbAccessTest : public ::testing::Test {
protected:
    Core::ProxyType<Plugin::UsbAccess> plugin;
    Core::JSONRPC::Handler& handler;
    Core::JSONRPC::Handler& handlerV2;
    Core::JSONRPC::Context context;
    string response;

    UsbAccessTest()
        : plugin(Core::ProxyType<Plugin::UsbAccess>::Create())
        , handler(*(plugin))
        , handlerV2(*(plugin->GetHandler(2)))
    {
    }
};

TEST_F(UsbAccessTest, RegisteredMethods)
{
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("getFileList")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("createLink")));
    EXPECT_EQ(Core::ERROR_NONE, handler.Exists(_T("clearLink")));
    EXPECT_EQ(Core::ERROR_NONE, handlerV2.Exists(_T("getFileList")));
    EXPECT_EQ(Core::ERROR_NONE, handlerV2.Exists(_T("createLink")));
    EXPECT_EQ(Core::ERROR_NONE, handlerV2.Exists(_T("clearLink")));
    EXPECT_EQ(Core::ERROR_NONE, handlerV2.Exists(_T("getAvailableFirmwareFiles")));
    EXPECT_EQ(Core::ERROR_NONE, handlerV2.Exists(_T("getMounted")));
    EXPECT_EQ(Core::ERROR_NONE, handlerV2.Exists(_T("updateFirmware")));
    EXPECT_EQ(Core::ERROR_NONE, handlerV2.Exists(_T("ArchiveLogs")));
}

TEST_F(UsbAccessTest, UpdateFirmware)
{
    UdevImplMock udevImplMock;
    WrapsImplMock wrapsImplMock;

    Udev::getInstance().impl = &udevImplMock;
    Wraps::getInstance().impl = &wrapsImplMock;

    EXPECT_CALL(wrapsImplMock, system(::testing::_))
        .Times(1)
        .WillOnce(::testing::Invoke(
            [&](const char* command) {
                EXPECT_EQ(string(command), string(_T("/lib/rdk/userInitiatedFWDnld.sh usb '/tmp;reboot;' 'my.bin' 0 >> /opt/logs/swupdate.log &")));

                return 0;
            }));

    EXPECT_EQ(Core::ERROR_NONE, handlerV2.Invoke(context, _T("updateFirmware"), _T("{\"fileName\":\"/tmp;reboot;/my.bin\"}"), response));
    EXPECT_EQ(response, string("{\"success\":true}"));

    EXPECT_EQ(Core::ERROR_GENERAL, handlerV2.Invoke(context, _T("updateFirmware"), _T("{\"fileName\":\"/tmp\';reboot;/my.bin\"}"), response));

    Udev::getInstance().impl = nullptr;
    Wraps::getInstance().impl = nullptr;
}
