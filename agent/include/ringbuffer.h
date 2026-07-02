// agent/include/ringbuffer.h
#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include "normalized_event.h"

class RingBuffer {
private:
    static const size_t RingBufferSize = 65536; // 64K events
    std::queue<std::shared_ptr<NormalizedEvent>> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    size_t m_maxSize;

public:
    RingBuffer(size_t maxSize = RingBufferSize) : m_maxSize(maxSize) {}

    bool Push(std::shared_ptr<NormalizedEvent> evt) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.size() >= m_maxSize) {
            return false; // Queue full - drop event
        }
        m_queue.push(evt);
        m_cond.notify_one();
        return true;
    }

    std::shared_ptr<NormalizedEvent> Pop() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cond.wait(lock, [this]() { return !m_queue.empty(); });
        
        auto evt = m_queue.front();
        m_queue.pop();
        return evt;
    }

    size_t Size() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.size();
    }
};
