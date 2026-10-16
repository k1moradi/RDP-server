// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_clipboard_adapter.h"

#import <AppKit/AppKit.h>

namespace rdp::macos
{
namespace
{

[[nodiscard]] NSPasteboard *nativePasteboard(void *context) noexcept
{
    return (__bridge NSPasteboard *)context;
}

[[nodiscard]] bool nativeReadChangeCount(
    void *context, std::uint64_t &changeCount) noexcept
{
    @try
    {
        NSPasteboard *pasteboard = nativePasteboard(context);
        if (pasteboard == nil)
        {
            return false;
        }
        const NSInteger nativeCount = pasteboard.changeCount;
        if (nativeCount < 0)
        {
            return false;
        }
        changeCount = static_cast<std::uint64_t>(nativeCount);
        return true;
    }
    @catch (NSException *)
    {
        return false;
    }
}

[[nodiscard]] bool nativeReplaceContents(
    void *context, const MacClipboardNativeContent &content) noexcept
{
    if ((!content.hasText && !content.hasPng) ||
        (content.hasPng && content.pngBytes.empty()))
    {
        return false;
    }

    @try
    {
        NSPasteboard *pasteboard = nativePasteboard(context);
        if (pasteboard == nil)
        {
            return false;
        }

        NSPasteboardItem *item = [[NSPasteboardItem alloc] init];
        if (item == nil)
        {
            return false;
        }

        if (content.hasText)
        {
            NSString *text = content.utf8Text.empty()
                ? @""
                : [[NSString alloc]
                    initWithBytes:content.utf8Text.data()
                           length:content.utf8Text.size()
                         encoding:NSUTF8StringEncoding];
            if (text == nil ||
                ![item setString:text forType:NSPasteboardTypeString])
            {
                return false;
            }
        }

        if (content.hasPng)
        {
            NSData *png = [NSData
                dataWithBytes:content.pngBytes.data()
                       length:content.pngBytes.size()];
            if (png == nil ||
                ![item setData:png forType:NSPasteboardTypePNG])
            {
                return false;
            }
        }

        (void)[pasteboard clearContents];
        if (![pasteboard writeObjects:@[ item ]])
        {
            // Do not leave a partially advertised remote item behind.
            (void)[pasteboard clearContents];
            return false;
        }
        return true;
    }
    @catch (NSException *)
    {
        return false;
    }
}

[[nodiscard]] bool nativeClearContents(void *context) noexcept
{
    @try
    {
        NSPasteboard *pasteboard = nativePasteboard(context);
        if (pasteboard == nil)
        {
            return false;
        }
        (void)[pasteboard clearContents];
        return true;
    }
    @catch (NSException *)
    {
        return false;
    }
}

} // namespace

MacClipboardNativeOperations makeMacClipboardNativeOperations() noexcept
{
    NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
    if (pasteboard == nil)
    {
        return {};
    }
    return {
        (__bridge void *)pasteboard,
        &nativeReadChangeCount,
        &nativeReplaceContents,
        &nativeClearContents,
    };
}

} // namespace rdp::macos
