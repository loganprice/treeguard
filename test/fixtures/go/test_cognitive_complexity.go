package fixtures

import "fmt"

// ruleid: go-cognitive-complexity
func HighComplexityFunction(x, y int) int {
	if x > 0 {
		for i := 0; i < 10; i++ {
			if y > 5 {
				switch x {
				case 1:
					for y < 100 {
						if x == y {
							y++
						}
					}
				default:
					fmt.Println("default")
				}
			}
		}
	}
	return y
}

// ok: go-cognitive-complexity
func SimpleFunction(x int) int {
	if x > 0 {
		return x * 2
	}
	return x
}
