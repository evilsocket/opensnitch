package socketsmonitor

import "testing"

// A task configuration arrives as decoded JSON from the GUI. A missing or
// wrong-typed field must be a reported error, not a panic that takes the whole
// daemon down.

func TestInitConfigValid(t *testing.T) {
	cfg, err := initConfig(map[string]interface{}{
		"interval": "3s",
		"state":    float64(1),
		"proto":    float64(2),
		"family":   float64(10),
	})
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.Interval != "3s" || cfg.State != 1 || cfg.Proto != 2 || cfg.Family != 10 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestInitConfigMissingFieldErrorsNoPanic(t *testing.T) {
	// "state" absent: this used to panic with
	// "interface conversion: interface {} is nil, not float64".
	_, err := initConfig(map[string]interface{}{
		"interval": "3s",
		"proto":    float64(0),
		"family":   float64(0),
	})
	if err == nil {
		t.Fatal("missing field should be an error")
	}
}

func TestInitConfigWrongTypeErrorsNoPanic(t *testing.T) {
	_, err := initConfig(map[string]interface{}{
		"interval": "3s",
		"state":    "not-a-number",
		"proto":    float64(0),
		"family":   float64(0),
	})
	if err == nil {
		t.Fatal("a non-numeric numeric field should be an error")
	}
}

func TestInitConfigIntervalDefaults(t *testing.T) {
	cfg, err := initConfig(map[string]interface{}{
		"state":  float64(0),
		"proto":  float64(0),
		"family": float64(0),
	})
	if err != nil {
		t.Fatalf("config without interval rejected: %v", err)
	}
	if cfg.Interval != "5s" {
		t.Fatalf("interval default not applied: %q", cfg.Interval)
	}
}

func TestInitConfigNotAMap(t *testing.T) {
	if _, err := initConfig("nonsense"); err == nil {
		t.Fatal("a non-object config should be an error")
	}
}
