// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Adapted from k1moradi/3DImageMaster with the project owner's explicit
// authorization. Kept self-contained so RDP-server has one canonical Qt
// toggle implementation for the upcoming single-page Start/Stop UI.

#include <QAbstractButton>
#include <QColor>
#include <QEvent>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QSize>
#include <QVariantAnimation>

namespace rdp::gui
{

class ToggleSwitchWidget final : public QAbstractButton
{
public:
    explicit ToggleSwitchWidget(QWidget* parentWidget = nullptr);
    ~ToggleSwitchWidget() override = default;

    ToggleSwitchWidget(const ToggleSwitchWidget&) = delete;
    ToggleSwitchWidget& operator=(const ToggleSwitchWidget&) = delete;
    ToggleSwitchWidget(ToggleSwitchWidget&&) = delete;
    ToggleSwitchWidget& operator=(ToggleSwitchWidget&&) = delete;

    [[nodiscard]] QSize sizeHint() const override;
    [[nodiscard]] QSize minimumSizeHint() const override;

protected:
    void checkStateSet() override;
    void nextCheckState() override;
    void mousePressEvent(QMouseEvent* mouseEventArg) override;
    void mouseMoveEvent(QMouseEvent* mouseEventArg) override;
    void mouseReleaseEvent(QMouseEvent* mouseEventArg) override;
    void paintEvent(QPaintEvent* paintEventArg) override;
    void changeEvent(QEvent* changeEventArg) override;

private:
    static constexpr int kDefaultWidth = 46;
    static constexpr int kDefaultHeight = 26;
    static constexpr int kMinimumWidth = 36;
    static constexpr int kMinimumHeight = 20;
    static constexpr int kLabelSpacing = 6;
    static constexpr int kAnimationDurationMilliseconds = 140;
    static constexpr qreal kThumbPadding = 2.5;
    static constexpr qreal kBorderPenWidth = 1.0;
    static constexpr qreal kDragThresholdPixels = 3.0;
    static constexpr qreal kToggleThreshold = 0.5;

    static constexpr QColor kActiveTrackColor{26, 115, 232};
    static constexpr QColor kActiveBorderColor{40, 130, 245};
    static constexpr QColor kInactiveTrackColor{53, 58, 64};
    static constexpr QColor kInactiveBorderColor{74, 80, 88};
    static constexpr QColor kThumbColor{218, 222, 227};
    static constexpr int kDisabledAlphaChannel = 110;

    [[nodiscard]] static qreal clampThumbPosition(qreal thumbPosition) noexcept;
    [[nodiscard]] qreal calculateTrackWidth() const;
    [[nodiscard]] qreal calculateTrackHeight() const noexcept;
    [[nodiscard]] qreal calculateThumbDiameter() const;
    [[nodiscard]] qreal calculateTravelDistance() const;
    void triggerAnimation(qreal targetThumbPosition);
    void recalculateCachedColors() noexcept;

    qreal thumbPosition_{0.0};
    bool dragOccurred_{false};
    bool leftButtonPressed_{false};
    qreal dragStartPositionX_{0.0};
    qreal dragStartThumbPosition_{0.0};

    QColor cachedTrackColor_;
    QColor cachedBorderColor_;
    QColor cachedThumbColor_;

    QVariantAnimation animation_;
};

} // namespace rdp::gui
