package aws

import (
	"fmt"
	"time"
)

func SafeRetry(actionName string, retries int, baseSleep time.Duration, fn func() error) error {
	if retries < 1 {
		retries = 1
	}
	var last error
	for i := 0; i < retries; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(time.Duration(float64(baseSleep) * (1.0 + float64(i)*0.35)))
	}
	return fmt.Errorf("%s 失败：%v", actionName, last)
}
