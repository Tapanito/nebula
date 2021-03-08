package nebula

import (
	"fmt"
	"testing"
)

func TestNewPacketCache(t *testing.T) {
	pc := NewPacketCache()

	fmt.Println(pc.timer.tickDuration)
	fmt.Println(pc.timer.wheelDuration)
	fmt.Println(pc.timer.wheelLen)
}
