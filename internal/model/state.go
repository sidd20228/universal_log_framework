package model

import "fmt"

// ReceiptState describes durable progress for one accepted occurrence.
type ReceiptState string

const (
	StateAccepted          ReceiptState = "ACCEPTED"
	StateProcessing        ReceiptState = "PROCESSING"
	StateRevisionCommitted ReceiptState = "REVISION_COMMITTED"
	StateDeliveryPending   ReceiptState = "DELIVERY_PENDING"
	StateDelivered         ReceiptState = "DELIVERED"
	StateDeadLetter        ReceiptState = "DEAD_LETTER"
)

var validReceiptStates = map[ReceiptState]struct{}{
	StateAccepted:          {},
	StateProcessing:        {},
	StateRevisionCommitted: {},
	StateDeliveryPending:   {},
	StateDelivered:         {},
	StateDeadLetter:        {},
}

var receiptTransitions = map[ReceiptState]map[ReceiptState]struct{}{
	StateAccepted: {
		StateProcessing: {},
	},
	StateProcessing: {
		StateAccepted:          {},
		StateRevisionCommitted: {},
		StateDeadLetter:        {},
	},
	StateRevisionCommitted: {
		StateDeliveryPending: {},
		StateDelivered:       {},
	},
	StateDeliveryPending: {
		StateDelivered:  {},
		StateDeadLetter: {},
	},
	StateDelivered: {
		// Reprocessing can commit another revision that requires delivery.
		StateDeliveryPending: {},
	},
	StateDeadLetter: {
		StateAccepted:        {},
		StateDeliveryPending: {},
	},
}

func (state ReceiptState) Valid() bool {
	_, ok := validReceiptStates[state]
	return ok
}

func (state ReceiptState) Terminal() bool {
	return state == StateDelivered || state == StateDeadLetter
}

func CanTransition(from, to ReceiptState) bool {
	if !from.Valid() || !to.Valid() || from == to {
		return false
	}
	_, ok := receiptTransitions[from][to]
	return ok
}

func ValidateTransition(from, to ReceiptState) error {
	if !from.Valid() {
		return fmt.Errorf("invalid current receipt state %q", from)
	}
	if !to.Valid() {
		return fmt.Errorf("invalid next receipt state %q", to)
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("receipt state transition %s -> %s is not allowed", from, to)
	}
	return nil
}
