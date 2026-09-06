// progress.h -- the terminal progress indicator, standing in for the Dart
// `console_bars` FillingBar the original tool used. Unlike the Go port it is
// advanced a whole GPU batch at a time, so it redraws on a timer rather than
// on every mnemonic.
#ifndef PROGRESS_H
#define PROGRESS_H

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>

struct Progress {
    std::string desc;
    int64_t total, count = 0;
    std::chrono::steady_clock::time_point start, lastDraw;
    bool showTotal;
    int width = 40;

    Progress(std::string desc_, int64_t total_, bool showTotal_)
        : desc(std::move(desc_)), total(total_), showTotal(showTotal_) {
        start = std::chrono::steady_clock::now();
        lastDraw = start - std::chrono::seconds(1);
    }

    void add(int64_t n, bool force = false) {
        count += n;
        auto now = std::chrono::steady_clock::now();
        if (force || now - lastDraw >= std::chrono::milliseconds(100)) draw();
    }

    void draw() {
        lastDraw = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(lastDraw - start).count();
        double rate = elapsed > 0 ? (double)count / elapsed : 0;

        if (showTotal && total > 0) {
            double pct = std::min(1.0, (double)count / (double)total);
            int filled = (int)(pct * width);
            std::string bar(filled, '=');
            bar.resize(width, ' ');
            printf("\r%s [%s] %lld/%lld (%.4f%%)  %.0f/s  eta %s   ", desc.c_str(), bar.c_str(),
                   (long long)count, (long long)total, pct * 100, rate, eta(rate).c_str());
        } else {
            std::string bar(width, ' ');
            printf("\r%s [%s] %lld  %.0f/s  %.0fs   ", desc.c_str(), bar.c_str(), (long long)count,
                   rate, elapsed);
        }
        fflush(stdout);
    }

    std::string eta(double rate) const {
        if (rate <= 0 || count >= total) return "--";
        double secs = (double)(total - count) / rate;
        char b[64];
        if (secs < 90) snprintf(b, sizeof(b), "%.0f seconds", secs);
        else if (secs < 5400) snprintf(b, sizeof(b), "%.1f minutes", secs / 60);
        else if (secs < 172800) snprintf(b, sizeof(b), "%.1f hours", secs / 3600);
        else if (secs < 94608000) snprintf(b, sizeof(b), "%.1f days", secs / 86400);
        else snprintf(b, sizeof(b), "%.1f years", secs / 31536000);
        return b;
    }

    void finish() {
        draw();
        printf("\n");
    }
};

#endif  // PROGRESS_H
