package shaping

import (
	"context"
	"math"
	"sync"
	"time"
)

type Limiter struct {
	download bucket
	upload   bucket
}

type bucket struct {
	mu        sync.Mutex
	rate      float64
	burstBits float64
	tokens    float64
	last      time.Time
}

func NewLimiter(policy Policy) (*Limiter, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	policy = policy.Effective()
	burstBits := float64(policy.BurstBytes) * 8
	return &Limiter{
		download: bucket{rate: float64(policy.DownloadBitsPerSecond), burstBits: burstBits, tokens: burstBits},
		upload:   bucket{rate: float64(policy.UploadBitsPerSecond), burstBits: burstBits, tokens: burstBits},
	}, nil
}

// Wait reserves capacity for a packet. It returns immediately for an unlimited
// direction and honors cancellation while a shaped packet is waiting.
func (l *Limiter) Wait(ctx context.Context, direction Direction, packetBytes int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateDirection(direction); err != nil {
		return err
	}
	if packetBytes <= 0 {
		return nil
	}
	eligibleAt, err := l.EligibleAt(time.Now(), direction, packetBytes)
	if err != nil {
		return err
	}
	delay := time.Until(eligibleAt)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// EligibleAt reserves capacity without blocking and returns when a scheduler
// may transmit the packet. Reservations preserve packet order within a flow.
func (l *Limiter) EligibleAt(now time.Time, direction Direction, packetBytes int) (time.Time, error) {
	if err := validateDirection(direction); err != nil {
		return time.Time{}, err
	}
	if packetBytes <= 0 {
		return now, nil
	}
	return now.Add(l.bucket(direction).reserve(now, packetBytes)), nil
}

func (l *Limiter) bucket(direction Direction) *bucket {
	if direction == Download {
		return &l.download
	}
	return &l.upload
}

func (b *bucket) reserve(now time.Time, packetBytes int) time.Duration {
	if b.rate == 0 || packetBytes <= 0 {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.last = now
	}
	base := now
	if now.After(b.last) {
		b.tokens = math.Min(b.burstBits, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	} else if b.last.After(now) {
		base = b.last
	}
	required := float64(packetBytes) * 8
	if b.tokens >= required {
		b.tokens -= required
		return base.Sub(now)
	}
	deficit := required - b.tokens
	b.tokens = 0
	delay := durationForBits(deficit, b.rate)
	b.last = base.Add(delay)
	return b.last.Sub(now)
}

func durationForBits(bits, rate float64) time.Duration {
	if bits <= 0 || rate <= 0 {
		return 0
	}
	return time.Duration(math.Ceil(bits / rate * float64(time.Second)))
}
