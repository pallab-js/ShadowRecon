use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::IpAddr;

/// Adaptive timing engine for congestion control and RTT tracking
pub struct AdaptiveTiming {
    // RTT tracking for each host
    // (IpAddr -> (Smooth RTT, RTT Var))
    hosts: Arc<Mutex<HashMap<IpAddr, (Duration, Duration)>>>,
    
    // Global scan speed/delay
    current_delay: Arc<Mutex<Duration>>,
    min_delay: Duration,
    max_delay: Duration,
}

impl AdaptiveTiming {
    pub fn new(initial_delay: Duration, min_rate: Option<f64>, max_rate: Option<f64>) -> Self {
        let min_delay = max_rate.map(|r| Duration::from_secs_f64(1.0 / r)).unwrap_or(Duration::from_micros(10));
        let max_delay = min_rate.map(|r| Duration::from_secs_f64(1.0 / r)).unwrap_or(Duration::from_secs(5));

        Self {
            hosts: Arc::new(Mutex::new(HashMap::new())),
            current_delay: Arc::new(Mutex::new(initial_delay.clamp(min_delay, max_delay))),
            min_delay,
            max_delay,
        }
    }

    /// Update RTT for a host
    pub fn update_rtt(&self, host: IpAddr, rtt: Duration) {
        let mut hosts = self.hosts.lock().unwrap();
        let entry = hosts.entry(host).or_insert((rtt, rtt / 2));
        
        let (srtt, rttvar) = entry;
        
        let diff = if *srtt > rtt { *srtt - rtt } else { rtt - *srtt };
        *rttvar = rttvar.mul_f32(0.75) + diff.mul_f32(0.25);
        *srtt = srtt.mul_f32(0.875) + rtt.mul_f32(0.125);
    }

    /// Get timeout for a host
    pub fn get_timeout(&self, host: IpAddr) -> Duration {
        let hosts = self.hosts.lock().unwrap();
        if let Some((srtt, rttvar)) = hosts.get(&host) {
            // RTO = SRTT + 4 * RTTVAR
            *srtt + *rttvar * 4
        } else {
            Duration::from_millis(1000) // Default timeout
        }
    }

    /// Get current inter-packet delay
    pub fn get_delay(&self) -> Duration {
        *self.current_delay.lock().unwrap()
    }

    /// Adjust delay based on congestion (loss)
    pub fn backoff(&self) {
        let mut delay = self.current_delay.lock().unwrap();
        *delay = (*delay).mul_f32(1.5).min(self.max_delay);
    }

    /// Adjust delay based on success
    pub fn speed_up(&self) {
        let mut delay = self.current_delay.lock().unwrap();
        *delay = (*delay).mul_f32(0.95).max(self.min_delay);
    }
}

impl Clone for AdaptiveTiming {
    fn clone(&self) -> Self {
        Self {
            hosts: Arc::clone(&self.hosts),
            current_delay: Arc::clone(&self.current_delay),
            min_delay: self.min_delay,
            max_delay: self.max_delay,
        }
    }
}
