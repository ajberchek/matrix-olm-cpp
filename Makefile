FILES=`find src tests -type f -type f \( -iname "*.cpp" -o -iname "*.hpp" \)`

default:
	@cmake . -Bbuild
	@cmake --build build

lint:
	@bash .make/clangFormatDiff.sh ${FILES} || true
	@clang-format -i ${FILES}

test:
	@./build/test_interface

clean:
	rm -rf build
