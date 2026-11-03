import SwiftUI

/// A soft toggle chip, for filters.
struct ZenChip: View {
    let title: String
    var symbol: String?
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                if let symbol { Image(systemName: symbol).font(.system(size: 10, weight: .medium)) }
                Text(title).font(.system(size: 11.5, weight: selected ? .semibold : .regular, design: .rounded))
            }
            .foregroundStyle(selected ? Theme.ink : Theme.inkSoft)
            .padding(.horizontal, 10)
            .frame(height: 24)
            .background {
                Capsule(style: .continuous)
                    .fill(selected ? Theme.cardStrong : Theme.card)
                    .overlay { if selected { Capsule(style: .continuous).fill(Theme.calmSoft) } }
            }
            .overlay(Capsule(style: .continuous).strokeBorder(selected ? Theme.sage.opacity(0.35) : Theme.hairline, lineWidth: 0.5))
            .contentShape(Capsule())
            .fixedSize()
        }
        .buttonStyle(.plain)
    }
}

/// A smaller cousin of the main tab strip.
struct ZenSegmented<Value: Hashable>: View {
    let options: [(value: Value, title: String)]
    let selection: Value
    let select: (Value) -> Void

    var body: some View {
        HStack(spacing: 2) {
            ForEach(options, id: \.value) { option in
                let selected = option.value == selection
                Button { select(option.value) } label: {
                    Text(option.title)
                        .font(.system(size: 12, weight: selected ? .semibold : .regular, design: .rounded))
                        .foregroundStyle(selected ? Theme.ink : Theme.inkSoft)
                        .padding(.horizontal, 12)
                        .frame(height: 24)
                        .background {
                            if selected {
                                Capsule(style: .continuous)
                                    .fill(Theme.cardStrong)
                                    .overlay(Capsule(style: .continuous).fill(Theme.calmSoft))
                                    .overlay(Capsule(style: .continuous).strokeBorder(Theme.hairline, lineWidth: 0.5))
                                    .shadow(color: Theme.shadow, radius: 2, y: 1)
                            }
                        }
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(2.5)
        .background(Theme.card, in: Capsule(style: .continuous))
        .overlay(Capsule(style: .continuous).strokeBorder(Theme.hairline, lineWidth: 0.5))
        .fixedSize()
    }
}

/// A rounded search field.
struct ZenSearchField: View {
    let prompt: String
    @Binding var text: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.inkFaint)
            TextField(prompt, text: $text)
                .textFieldStyle(.plain)
                .font(.system(size: 12, design: .rounded))
                .foregroundStyle(Theme.ink)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 11)).foregroundStyle(Theme.inkFaint)
                }
                .buttonStyle(.plain)
                .help("Clear")
            }
        }
        .padding(.horizontal, 10)
        .frame(height: 26)
        .background(Theme.cardStrong, in: Capsule(style: .continuous))
        .overlay(Capsule(style: .continuous).strokeBorder(Theme.hairline, lineWidth: 0.5))
    }
}

/// A quiet text link with a small symbol.
struct QuietLink: View {
    let title: String
    let symbol: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.system(size: 12, weight: .medium, design: .rounded))
                .foregroundStyle(Theme.moss)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// A tiny bar of a day's alerts: clay for important, sand for worth a look, mist for low.
struct DayMoodBar: View {
    let summary: DaySummary?
    var width: CGFloat = 40

    var body: some View {
        let s = summary
        let parts: [(Color, UInt32)] = [
            (Severity.high.color, s?.important ?? 0),
            (Severity.medium.color, s?.worthALook ?? 0),
            (Severity.low.color, s?.count(.low) ?? 0),
        ].filter { $0.1 > 0 }
        let total = max(1, parts.reduce(0) { $0 + $1.1 })
        HStack(spacing: 1.5) {
            if parts.isEmpty {
                Circle().fill((s?.events ?? 0) > 0 ? Theme.sage.opacity(0.55) : Theme.hairline).frame(width: 6, height: 6)
                Spacer(minLength: 0)
            } else {
                ForEach(Array(parts.enumerated()), id: \.offset) { _, part in
                    Capsule(style: .continuous)
                        .fill(part.0.opacity(0.85))
                        .frame(width: max(5, (width - 3) * CGFloat(part.1) / CGFloat(total)), height: 5)
                }
                Spacer(minLength: 0)
            }
        }
        .frame(width: width, height: 6)
    }
}

/// Heatmap colour for a day: pale sage when calm, sand then clay as alerts warm it up.
func heatColor(_ s: DaySummary?) -> Color {
    guard let s, s.events > 0 else { return Theme.hairline }
    if s.important > 0 { return Severity.high.color.opacity(0.8) }
    if s.worthALook > 0 { return Severity.medium.color.opacity(0.7) }
    let busy = min(Double(s.events), 60) / 60
    return Theme.sage.opacity(0.22 + 0.33 * busy)
}

func durationText(_ secs: UInt64) -> String {
    let h = secs / 3600, m = secs % 3600 / 60
    if h > 0 { return "\(h)h \(m)m" }
    return m > 0 ? "\(m)m" : "a moment"
}

func timeText(_ unix: UInt64) -> String {
    Date(timeIntervalSince1970: TimeInterval(unix)).formatted(date: .omitted, time: .shortened)
}

func dateText(_ unix: UInt64) -> String {
    Date(timeIntervalSince1970: TimeInterval(unix)).formatted(.dateTime.day().month(.abbreviated))
}
