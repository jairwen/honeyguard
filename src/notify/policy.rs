//! 出站限流：令牌桶（PRD ALR-04）。聚合与静默的判定依赖分发器会话状态，内联在 [`super`] 中。

use tokio::time::Instant;

/// 令牌桶：容量 = 每分钟配额（允许瞬时突发），按 quota/60 每秒回填。
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(quota_per_min: u32) -> Self {
        let quota = quota_per_min.max(1) as f64;
        Self {
            capacity: quota,
            refill_per_sec: quota / 60.0,
            tokens: quota,
            last: Instant::now(),
        }
    }

    /// 尝试取一个令牌；now 显式传入便于测试。
    pub fn try_acquire(&mut self, now: Instant) -> bool {
        let elapsed = now
            .checked_duration_since(self.last)
            .unwrap_or_default()
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_exhaust_then_refill() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(2); // 容量 2，每秒回填 2/60
        assert!(rl.try_acquire(t0));
        assert!(rl.try_acquire(t0));
        assert!(!rl.try_acquire(t0), "桶空后应拒绝");
        assert!(
            !rl.try_acquire(t0 + Duration::from_secs(1)),
            "1 秒仅回填 ~0.03 个令牌"
        );
        assert!(
            rl.try_acquire(t0 + Duration::from_secs(60)),
            "60 秒后应回满"
        );
        assert!(rl.try_acquire(t0 + Duration::from_secs(60)));
        assert!(!rl.try_acquire(t0 + Duration::from_secs(60)), "再次耗尽");
    }

    #[test]
    fn zero_quota_floors_to_one() {
        let mut rl = RateLimiter::new(0);
        assert!(rl.try_acquire(Instant::now()));
    }
}
