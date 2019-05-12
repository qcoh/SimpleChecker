#include <cstdint>
#include <limits>
#include <string>

#include <type_traits>

class A
{
public:
	A() = default;
	A(const A &) {}
	static std::uint8_t instanceId;
	static float const pi;
	static std::string const seperator;
};

static_assert(!std::is_pod<A>::value);

std::uint8_t A::instanceId = 0;
float const A::pi = 3.14;
std::string const A::seperator = "===";

class B
{
public:
private:
	static A a;
};

class C
{
public:
	constexpr C() = default;
	C(const C &) {}
};
static_assert(!std::is_pod<C>::value);

namespace
{
constexpr std::int32_t maxInt32 = std::numeric_limits<std::int32_t>::max();
A instance{};

constexpr C c{};

} // namespace

void fn() noexcept
{
	static A a{};
	static std::int32_t counter{0};
}

class D
{
public:
private:
	static B *instance;
};

B *D::instance = nullptr;
