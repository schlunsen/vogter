import AppKit

/// Vogter's own menu bar mark: the shield from the app icon, drawn as a template
/// image so macOS tints it for light, dark and highlighted menu bars.
///
/// One shape in every state, so the icon stays recognisable and only its weight
/// changes: an outline while calm, an outline with a mark for "worth a look", a
/// solid shield for "needs a look", and a dashed outline while not connected.
enum MenuBarIcon {
    enum State {
        /// Nothing above info.
        case calm
        /// Medium findings.
        case look
        /// High or critical findings.
        case alert
        /// No connection to the service.
        case resting
    }

    /// Drawn on an 18 pt grid; `size` scales it (the popover header uses a larger one).
    static func image(_ state: State, size: CGFloat = 18) -> NSImage {
        let image = NSImage(size: NSSize(width: size, height: size), flipped: true) { _ in
            let scale = AffineTransform(scaleByX: size / 18, byY: size / 18)
            let shield = shieldPath()
            shield.transform(using: scale)
            shield.lineWidth = 1.5 * size / 18
            shield.lineJoinStyle = .round
            NSColor.black.setStroke()
            NSColor.black.setFill()

            switch state {
            case .calm:
                shield.stroke()
                // The drop at the centre of the app icon.
                let drop = NSBezierPath(ovalIn: NSRect(x: 7.3, y: 6.9, width: 3.4, height: 3.4))
                drop.transform(using: scale)
                drop.fill()
            case .look:
                shield.stroke()
                mark(scale).fill()
            case .alert:
                shield.fill()
                shield.stroke()
                // Punch the mark out of the solid shield.
                NSGraphicsContext.current?.compositingOperation = .destinationOut
                mark(scale).fill()
            case .resting:
                NSColor.black.withAlphaComponent(0.6).setStroke()
                shield.setLineDash([2.2 * size / 18, 2.0 * size / 18], count: 2, phase: 0)
                shield.lineCapStyle = .round
                shield.stroke()
            }
            return true
        }
        image.isTemplate = true
        return image
    }

    /// A shield with soft shoulders and a rounded point, inset for a 1.5 pt stroke.
    private static func shieldPath() -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 9, y: 1.7))
        p.curve(to: NSPoint(x: 15.2, y: 4.0), controlPoint1: NSPoint(x: 10.8, y: 3.1), controlPoint2: NSPoint(x: 13.2, y: 3.9))
        p.line(to: NSPoint(x: 15.2, y: 8.6))
        p.curve(to: NSPoint(x: 9, y: 16.3), controlPoint1: NSPoint(x: 15.2, y: 12.4), controlPoint2: NSPoint(x: 12.5, y: 15.1))
        p.curve(to: NSPoint(x: 2.8, y: 8.6), controlPoint1: NSPoint(x: 5.5, y: 15.1), controlPoint2: NSPoint(x: 2.8, y: 12.4))
        p.line(to: NSPoint(x: 2.8, y: 4.0))
        p.curve(to: NSPoint(x: 9, y: 1.7), controlPoint1: NSPoint(x: 4.8, y: 3.9), controlPoint2: NSPoint(x: 7.2, y: 3.1))
        p.close()
        return p
    }

    /// An exclamation mark: a rounded bar and a dot.
    private static func mark(_ scale: AffineTransform) -> NSBezierPath {
        let p = NSBezierPath(roundedRect: NSRect(x: 8.15, y: 5.0, width: 1.7, height: 5.0), xRadius: 0.85, yRadius: 0.85)
        p.appendOval(in: NSRect(x: 8.0, y: 11.2, width: 2.0, height: 2.0))
        p.transform(using: scale)
        return p
    }
}
