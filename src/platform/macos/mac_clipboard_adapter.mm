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
    if ((!content.hasText && !content.hasPng && !content.hasFileUrls) ||
        (content.hasPng && content.pngBytes.empty()) ||
        (content.hasFileUrls &&
         (content.fileUrls.empty() ||
          content.fileUrls.size() >
              rdp_server::server::clipboard::RemoteTransfer::
                  kMaximumRemoteFiles ||
          content.hasText || content.hasPng)))
    {
        return false;
    }
    for (std::size_t index = 0; index < content.fileUrls.size(); ++index)
    {
        const std::string_view fileUrl = content.fileUrls[index];
        if (fileUrl.empty())
        {
            return false;
        }
        for (std::size_t previous = 0; previous < index; ++previous)
        {
            if (content.fileUrls[previous] == fileUrl)
            {
                return false;
            }
        }
    }

    @try
    {
        NSPasteboard *pasteboard = nativePasteboard(context);
        if (pasteboard == nil)
        {
            return false;
        }

        if (content.hasFileUrls)
        {
            NSMutableArray<NSURL *> *fileUrls =
                [NSMutableArray
                    arrayWithCapacity:content.fileUrls.size()];
            if (fileUrls == nil)
            {
                return false;
            }
            for (const std::string_view fileUrlView : content.fileUrls)
            {
                NSString *urlString = [[NSString alloc]
                    initWithBytes:fileUrlView.data()
                           length:fileUrlView.size()
                         encoding:NSUTF8StringEncoding];
                NSURL *fileUrl =
                    urlString != nil
                        ? [NSURL URLWithString:urlString]
                        : nil;
                if (fileUrl == nil || !fileUrl.isFileURL)
                {
                    return false;
                }
                [fileUrls addObject:fileUrl];
            }

            (void)[pasteboard clearContents];
            if (![pasteboard writeObjects:fileUrls])
            {
                (void)[pasteboard clearContents];
                return false;
            }
            return true;
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
