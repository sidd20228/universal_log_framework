package model

import "testing"

func TestReceiptStateTransitionsAreExact(t *testing.T) {
	states := []ReceiptState{
		StateAccepted,
		StateProcessing,
		StateRevisionCommitted,
		StateDeliveryPending,
		StateDelivered,
		StateDeadLetter,
	}
	want := map[[2]ReceiptState]bool{
		{StateAccepted, StateProcessing}:               true,
		{StateProcessing, StateAccepted}:               true,
		{StateProcessing, StateRevisionCommitted}:      true,
		{StateProcessing, StateDeadLetter}:             true,
		{StateRevisionCommitted, StateDeliveryPending}: true,
		{StateRevisionCommitted, StateDelivered}:       true,
		{StateDeliveryPending, StateDelivered}:         true,
		{StateDeliveryPending, StateDeadLetter}:        true,
		{StateDeadLetter, StateAccepted}:               true,
		{StateDeadLetter, StateDeliveryPending}:        true,
	}
	for _, from := range states {
		for _, to := range states {
			pair := [2]ReceiptState{from, to}
			if got := CanTransition(from, to); got != want[pair] {
				t.Errorf("CanTransition(%s, %s) = %t, want %t", from, to, got, want[pair])
			}
			if err := ValidateTransition(from, to); (err == nil) != want[pair] {
				t.Errorf("ValidateTransition(%s, %s) error = %v", from, to, err)
			}
		}
	}
}

func TestReceiptStateRejectsUnknownStates(t *testing.T) {
	if CanTransition(ReceiptState("MISSING"), StateAccepted) {
		t.Fatal("unknown source state was accepted")
	}
	if CanTransition(StateAccepted, ReceiptState("MISSING")) {
		t.Fatal("unknown target state was accepted")
	}
}

func TestReceiptStateTerminal(t *testing.T) {
	for _, test := range []struct {
		state ReceiptState
		want  bool
	}{
		{StateAccepted, false},
		{StateProcessing, false},
		{StateRevisionCommitted, false},
		{StateDeliveryPending, false},
		{StateDelivered, true},
		{StateDeadLetter, true},
	} {
		if got := test.state.Terminal(); got != test.want {
			t.Errorf("%s.Terminal() = %t, want %t", test.state, got, test.want)
		}
	}
}
