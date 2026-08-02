package shaping

import (
	"context"
	"time"
)

const (
	maximumIngressBatch          = 64
	monitorPriorityBurst         = 8
	schedulerMaintenanceInterval = 250 * time.Millisecond
)

type scheduledPacket struct {
	frame queuedFrame
	queue *directionalQueue
}

type scheduledFlow struct {
	key      schedulerFlowKey
	packets  []scheduledPacket
	readyAt  time.Time
	limited  bool
	prepared bool
}

type schedulerFlowKey struct {
	device    string
	direction Direction
}

// packetScheduler owns all per-device/per-direction flow state. It reserves
// limiter eligibility without blocking and is the only component that calls
// the transmitter, preserving serialized packet injection.
type packetScheduler struct {
	forwarder      *Forwarder
	flows          map[schedulerFlowKey]*scheduledFlow
	order          []schedulerFlowKey
	monitorCursor  int
	limitedCursor  int
	monitorStreak  int
	monitorFlows   int
	limitedFlows   int
	policyRevision uint64
}

func newPacketScheduler(forwarder *Forwarder) *packetScheduler {
	return &packetScheduler{
		forwarder:      forwarder,
		flows:          make(map[schedulerFlowKey]*scheduledFlow),
		policyRevision: forwarder.manager.policyRevision(),
	}
}

func (s *packetScheduler) run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			s.cancelAll()
			return
		}
		s.ingestAvailable(maximumIngressBatch)
		if ctx.Err() != nil {
			s.cancelAll()
			return
		}
		now := time.Now()
		if revision := s.forwarder.manager.policyRevision(); revision != s.policyRevision {
			s.pruneUnmanaged()
			s.policyRevision = revision
		}
		if flow := s.nextReady(now); flow != nil {
			s.transmit(ctx, flow)
			if ctx.Err() != nil {
				s.cancelAll()
				return
			}
			continue
		}

		wait, waiting := s.nextWait(now)
		var timer *time.Timer
		var timerC <-chan time.Time
		if waiting {
			timer = time.NewTimer(wait)
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			s.cancelAll()
			return
		case frame := <-s.forwarder.upload.frames:
			if timer != nil {
				timer.Stop()
			}
			s.add(frame, &s.forwarder.upload, time.Now())
		case frame := <-s.forwarder.download.frames:
			if timer != nil {
				timer.Stop()
			}
			s.add(frame, &s.forwarder.download, time.Now())
		case <-timerC:
		}
	}
}

func (s *packetScheduler) ingestAvailable(limit int) {
	for range limit {
		select {
		case frame := <-s.forwarder.upload.frames:
			s.add(frame, &s.forwarder.upload, time.Now())
		case frame := <-s.forwarder.download.frames:
			s.add(frame, &s.forwarder.download, time.Now())
		default:
			return
		}
	}
}

func (s *packetScheduler) add(frame queuedFrame, queue *directionalQueue, now time.Time) {
	key := flowKey(frame)
	flow := s.flows[key]
	if flow == nil {
		flow = &scheduledFlow{key: key}
		s.flows[key] = flow
		s.order = append(s.order, key)
	}
	wasEmpty := len(flow.packets) == 0
	flow.packets = append(flow.packets, scheduledPacket{frame: frame, queue: queue})
	if wasEmpty {
		s.prepare(flow, now)
	}
}

func flowKey(frame queuedFrame) schedulerFlowKey {
	return schedulerFlowKey{device: frame.deviceKey, direction: frame.direction}
}

func (s *packetScheduler) prepare(flow *scheduledFlow, now time.Time) {
	s.deactivate(flow)
	if len(flow.packets) == 0 {
		return
	}
	packet := flow.packets[0].frame
	readyAt, managed, limited, err := s.forwarder.manager.eligibleAtKey(now, packet.deviceKey, packet.direction, len(packet.data))
	flow.prepared = true
	flow.limited = limited
	flow.readyAt = readyAt
	if err != nil || !managed {
		flow.readyAt = now
	}
	if flow.limited {
		s.limitedFlows++
	} else {
		s.monitorFlows++
	}
}

func (s *packetScheduler) deactivate(flow *scheduledFlow) {
	if !flow.prepared {
		return
	}
	if flow.limited {
		s.limitedFlows--
	} else {
		s.monitorFlows--
	}
	flow.prepared = false
}

func (s *packetScheduler) nextReady(now time.Time) *scheduledFlow {
	var monitor, limited *scheduledFlow
	var monitorIndex, limitedIndex int
	if s.monitorFlows > 0 {
		monitor, monitorIndex = s.findReady(false, now, s.monitorCursor)
	}
	if s.limitedFlows > 0 {
		limited, limitedIndex = s.findReady(true, now, s.limitedCursor)
	}
	if monitor != nil && (s.monitorStreak < monitorPriorityBurst || limited == nil) {
		s.monitorCursor = (monitorIndex + 1) % len(s.order)
		s.monitorStreak++
		return monitor
	}
	if limited != nil {
		s.limitedCursor = (limitedIndex + 1) % len(s.order)
		s.monitorStreak = 0
		return limited
	}
	if monitor != nil {
		s.monitorCursor = (monitorIndex + 1) % len(s.order)
		s.monitorStreak++
		return monitor
	}
	return nil
}

func (s *packetScheduler) findReady(limited bool, now time.Time, cursor int) (*scheduledFlow, int) {
	if len(s.order) == 0 {
		return nil, 0
	}
	for offset := range len(s.order) {
		index := (cursor + offset) % len(s.order)
		flow := s.flows[s.order[index]]
		if flow != nil && len(flow.packets) > 0 && flow.prepared && flow.limited == limited && !flow.readyAt.After(now) {
			return flow, index
		}
	}
	return nil, 0
}

func (s *packetScheduler) nextWait(now time.Time) (time.Duration, bool) {
	var earliest time.Time
	for _, key := range s.order {
		flow := s.flows[key]
		if flow == nil || len(flow.packets) == 0 || !flow.prepared {
			continue
		}
		if earliest.IsZero() || flow.readyAt.Before(earliest) {
			earliest = flow.readyAt
		}
	}
	if earliest.IsZero() {
		return 0, false
	}
	return min(schedulerMaintenanceInterval, max(time.Duration(0), earliest.Sub(now))), true
}

func (s *packetScheduler) pruneUnmanaged() {
	kept := s.order[:0]
	for _, key := range s.order {
		flow := s.flows[key]
		if flow == nil {
			continue
		}
		if s.forwarder.manager.hasKey(flow.key.device) {
			kept = append(kept, key)
			continue
		}
		for _, packet := range flow.packets {
			packet.queue.release(packet.frame)
			s.forwarder.canceledDrops.Add(1)
		}
		flow.packets = nil
		s.deactivate(flow)
		delete(s.flows, key)
	}
	s.order = kept
	s.monitorCursor = 0
	s.limitedCursor = 0
}

func (s *packetScheduler) transmit(ctx context.Context, flow *scheduledFlow) {
	packet := flow.packets[0]
	frame := packet.frame
	if !s.forwarder.manager.hasKey(frame.deviceKey) {
		s.forwarder.canceledDrops.Add(1)
		s.finish(flow, packet, time.Now())
		return
	}
	if err := s.forwarder.sender.Send(ctx, frame.data); err != nil {
		if ctx.Err() != nil {
			s.forwarder.canceledDrops.Add(1)
		} else {
			s.forwarder.sendErrors.Add(1)
			select {
			case s.forwarder.errors <- err:
			default:
			}
		}
		s.finish(flow, packet, time.Now())
		return
	}
	s.forwarder.forwarded.Add(1)
	s.forwarder.recordTraffic(frame)
	s.finish(flow, packet, time.Now())
}

func (s *packetScheduler) finish(flow *scheduledFlow, packet scheduledPacket, now time.Time) {
	packet.queue.release(packet.frame)
	flow.packets[0] = scheduledPacket{}
	flow.packets = flow.packets[1:]
	s.prepare(flow, now)
}

func (s *packetScheduler) cancelAll() {
	for _, flow := range s.flows {
		for _, packet := range flow.packets {
			packet.queue.release(packet.frame)
			s.forwarder.canceledDrops.Add(1)
		}
		flow.packets = nil
		s.deactivate(flow)
	}
}
