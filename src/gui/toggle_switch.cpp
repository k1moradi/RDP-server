// SPDX-License-Identifier: GPL-3.0-or-later
#include "toggle_switch.h"

#include <QEasingCurve>
#include <QFontMetrics>
#include <QPainter>
#include <QPalette>
#include <QPen>
#include <QRectF>
#include <QSizePolicy>

#include <algorithm>
#include <cmath>

namespace rdp::gui
{

ToggleSwitchWidget::ToggleSwitchWidget(QWidget* parentWidget)
    : QAbstractButton(parentWidget)
{
    setCheckable(true);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    setCursor(Qt::PointingHandCursor);

    animation_.setDuration(kAnimationDurationMilliseconds);
    animation_.setEasingCurve(QEasingCurve::InOutQuad);
    animation_.setStartValue(0.0);
    animation_.setEndValue(0.0);

    connect(&animation_, &QVariantAnimation::valueChanged, this,
        [this](const QVariant& animationValue) {
            thumbPosition_ = animationValue.toReal();
            recalculateCachedColors();
            update();
        });

    recalculateCachedColors();
}

QSize ToggleSwitchWidget::sizeHint() const
{
    QSize preferredSize{kDefaultWidth, kDefaultHeight};
    if (!text().isEmpty())
    {
        const QFontMetrics metrics(font());
        preferredSize.setWidth(
            kDefaultWidth + kLabelSpacing + metrics.horizontalAdvance(text()));
        preferredSize.setHeight((std::max)(kDefaultHeight, metrics.height()));
    }
    return preferredSize;
}

QSize ToggleSwitchWidget::minimumSizeHint() const
{
    QSize minimumSize{kMinimumWidth, kMinimumHeight};
    if (!text().isEmpty())
    {
        const QFontMetrics metrics(font());
        minimumSize.setWidth(
            kDefaultWidth + kLabelSpacing + metrics.horizontalAdvance(text()));
        minimumSize.setHeight((std::max)(kDefaultHeight, metrics.height()));
    }
    return minimumSize;
}

void ToggleSwitchWidget::checkStateSet()
{
    QAbstractButton::checkStateSet();
    triggerAnimation(isChecked() ? 1.0 : 0.0);
}

void ToggleSwitchWidget::nextCheckState()
{
    if (dragOccurred_)
        return;

    QAbstractButton::nextCheckState();
    triggerAnimation(isChecked() ? 1.0 : 0.0);
}

void ToggleSwitchWidget::mousePressEvent(QMouseEvent* mouseEventArg)
{
    if (mouseEventArg->button() == Qt::LeftButton)
    {
        dragOccurred_ = false;
        leftButtonPressed_ =
            isEnabled() &&
            mouseEventArg->position().x() <= calculateTrackWidth();
        if (leftButtonPressed_)
        {
            animation_.stop();
            dragStartPositionX_ = mouseEventArg->position().x();
            dragStartThumbPosition_ = clampThumbPosition(thumbPosition_);
        }
    }
    else if (!leftButtonPressed_)
    {
        dragOccurred_ = false;
    }
    QAbstractButton::mousePressEvent(mouseEventArg);
}

void ToggleSwitchWidget::mouseMoveEvent(QMouseEvent* mouseEventArg)
{
    if (leftButtonPressed_ &&
        (mouseEventArg->buttons() & Qt::LeftButton) != 0)
    {
        const qreal horizontalDelta =
            mouseEventArg->position().x() - dragStartPositionX_;
        if (std::abs(horizontalDelta) > kDragThresholdPixels)
        {
            dragOccurred_ = true;
            animation_.stop();
            const qreal totalTravelDistance = calculateTravelDistance();
            const qreal normalizedDelta = totalTravelDistance > 0.0
                ? horizontalDelta / totalTravelDistance
                : 0.0;
            thumbPosition_ = clampThumbPosition(
                dragStartThumbPosition_ + normalizedDelta);
            recalculateCachedColors();
            update();
        }
    }
    QAbstractButton::mouseMoveEvent(mouseEventArg);
}

void ToggleSwitchWidget::mouseReleaseEvent(QMouseEvent* mouseEventArg)
{
    const bool leftButtonRelease =
        mouseEventArg->button() == Qt::LeftButton;
    if (dragOccurred_ && leftButtonRelease && leftButtonPressed_)
    {
        const bool finalState = thumbPosition_ >= kToggleThreshold;
        if (isChecked() != finalState)
            setChecked(finalState);
        else
            triggerAnimation(finalState ? 1.0 : 0.0);
    }

    QAbstractButton::mouseReleaseEvent(mouseEventArg);
    if (leftButtonRelease)
    {
        leftButtonPressed_ = false;
        dragOccurred_ = false;
    }
}

void ToggleSwitchWidget::changeEvent(QEvent* changeEventArg)
{
    QAbstractButton::changeEvent(changeEventArg);
    if (changeEventArg->type() == QEvent::EnabledChange)
    {
        if (!isEnabled())
        {
            leftButtonPressed_ = false;
            dragOccurred_ = false;
        }
        recalculateCachedColors();
        update();
    }
    else if (changeEventArg->type() == QEvent::FontChange ||
             changeEventArg->type() == QEvent::StyleChange)
    {
        updateGeometry();
        update();
    }
}

void ToggleSwitchWidget::paintEvent(QPaintEvent* /*paintEventArg*/)
{
    if (width() <= 0 || height() <= 0)
        return;

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const qreal currentHeight = static_cast<qreal>(height());
    const qreal trackWidth = calculateTrackWidth();
    const qreal trackHeight = calculateTrackHeight();
    const qreal trackCoordinateY =
        (std::max)(0.0, (currentHeight - trackHeight) * 0.5);

    constexpr qreal halfPenWidth = kBorderPenWidth * 0.5;
    const QRectF trackRectangle(
        halfPenWidth,
        trackCoordinateY + halfPenWidth,
        (std::max)(0.0, trackWidth - kBorderPenWidth),
        (std::max)(0.0, trackHeight - kBorderPenWidth));
    const qreal trackRadius = (std::max)(
        0.0, (std::min)(trackRectangle.width(), trackRectangle.height()) * 0.5);

    painter.setPen(QPen(cachedBorderColor_, kBorderPenWidth));
    painter.setBrush(cachedTrackColor_);
    painter.drawRoundedRect(trackRectangle, trackRadius, trackRadius);

    const qreal thumbDiameter = calculateThumbDiameter();
    const qreal travelDistance = calculateTravelDistance();
    const qreal thumbCoordinateX =
        kThumbPadding + clampThumbPosition(thumbPosition_) * travelDistance;
    const qreal thumbCoordinateY = trackCoordinateY + kThumbPadding;
    const QRectF thumbRectangle(
        thumbCoordinateX, thumbCoordinateY, thumbDiameter, thumbDiameter);

    if (thumbDiameter > 0.0)
    {
        painter.setPen(Qt::NoPen);
        painter.setBrush(cachedThumbColor_);
        painter.drawEllipse(thumbRectangle);
    }

    if (!text().isEmpty())
    {
        const qreal labelCoordinateX =
            trackWidth + static_cast<qreal>(kLabelSpacing);
        const QRectF labelRectangle(
            labelCoordinateX, 0.0,
            (std::max)(0.0, static_cast<qreal>(width()) - labelCoordinateX),
            currentHeight);
        const QPalette::ColorGroup group =
            isEnabled() ? QPalette::Active : QPalette::Disabled;
        painter.setPen(palette().color(group, QPalette::WindowText));
        painter.setBrush(Qt::NoBrush);
        painter.drawText(labelRectangle,
            Qt::AlignLeft | Qt::AlignVCenter | Qt::TextSingleLine, text());
    }
}

qreal ToggleSwitchWidget::clampThumbPosition(qreal thumbPosition) noexcept
{
    if (!std::isfinite(thumbPosition))
        return 0.0;
    return std::clamp(thumbPosition, 0.0, 1.0);
}

qreal ToggleSwitchWidget::calculateTrackWidth() const
{
    const qreal currentWidth =
        (std::max)(0.0, static_cast<qreal>(width()));
    if (text().isEmpty())
        return currentWidth;
    return (std::min)(currentWidth, static_cast<qreal>(kDefaultWidth));
}

qreal ToggleSwitchWidget::calculateTrackHeight() const noexcept
{
    return (std::min)(
        (std::max)(0.0, static_cast<qreal>(height())),
        static_cast<qreal>(kDefaultHeight));
}

qreal ToggleSwitchWidget::calculateThumbDiameter() const
{
    return (std::max)(
        0.0, calculateTrackHeight() - 2.0 * kThumbPadding);
}

qreal ToggleSwitchWidget::calculateTravelDistance() const
{
    const qreal thumbDiameter = calculateThumbDiameter();
    return (std::max)(
        0.0, calculateTrackWidth() - thumbDiameter - 2.0 * kThumbPadding);
}

void ToggleSwitchWidget::triggerAnimation(qreal targetThumbPosition)
{
    targetThumbPosition = clampThumbPosition(targetThumbPosition);
    if (isVisible())
    {
        animation_.stop();
        animation_.setStartValue(thumbPosition_);
        animation_.setEndValue(targetThumbPosition);
        animation_.start();
    }
    else
    {
        thumbPosition_ = targetThumbPosition;
        recalculateCachedColors();
        update();
    }
}

void ToggleSwitchWidget::recalculateCachedColors() noexcept
{
    thumbPosition_ = clampThumbPosition(thumbPosition_);

    const auto interpolate = [](
        int start, int end, qreal progress) noexcept -> int {
        return static_cast<int>(std::lerp(
            static_cast<qreal>(start),
            static_cast<qreal>(end),
            progress));
    };

    cachedTrackColor_ = QColor(
        interpolate(kInactiveTrackColor.red(),
                    kActiveTrackColor.red(), thumbPosition_),
        interpolate(kInactiveTrackColor.green(),
                    kActiveTrackColor.green(), thumbPosition_),
        interpolate(kInactiveTrackColor.blue(),
                    kActiveTrackColor.blue(), thumbPosition_));
    cachedBorderColor_ = QColor(
        interpolate(kInactiveBorderColor.red(),
                    kActiveBorderColor.red(), thumbPosition_),
        interpolate(kInactiveBorderColor.green(),
                    kActiveBorderColor.green(), thumbPosition_),
        interpolate(kInactiveBorderColor.blue(),
                    kActiveBorderColor.blue(), thumbPosition_));
    cachedThumbColor_ = kThumbColor;

    if (!isEnabled())
    {
        cachedTrackColor_.setAlpha(kDisabledAlphaChannel);
        cachedBorderColor_.setAlpha(kDisabledAlphaChannel);
        cachedThumbColor_.setAlpha(kDisabledAlphaChannel);
    }
}

} // namespace rdp::gui
