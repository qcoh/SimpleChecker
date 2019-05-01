#include <cstdint>
#include <limits>
#include <string>

class A {
public:
	static std::uint8_t instanceId;
	static float const pi;
	static std::string const seperator;
};

std::uint8_t A::instanceId = 0;
float const A::pi = 3.14;
std::string const A::seperator = "===";

int main() {
	A a;
	return a.instanceId;
}
