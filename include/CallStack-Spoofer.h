#pragma once
#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <ntdef.h>
#include <xtr1common> 
#else
#include <Windows.h>
#include <utility>
#endif
#include  <Intrin.h> 

/*
 *  Copyright 2022 Barracudach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 // === FAQ === documentation is available at https://github.com/Barracudach
//Supports 2 modes: kernelmode and usermode(x64)
//For kernel- disable Control Flow Guard (CFG) /guard:cf 
//usermode c++17 and above
//kernelmode c++14 and above



#define SPOOF_FUNC CallSpoofer::SpoofFunction spoof(_AddressOfReturnAddress());
#ifdef _KERNEL_MODE
#define SPOOF_CALL(ret_type,name) (CallSpoofer::SafeCall<ret_type,std::remove_reference_t<decltype(*name)>>(name))
#else
#define SPOOF_CALL(name) (CallSpoofer::SafeCall(name))
#endif


#define MAX_FUNC_BUFFERED 100
#define SHELLCODE_GENERATOR_SIZE 500

namespace CallSpoofer
{
#ifdef _KERNEL_MODE
	typedef unsigned __int64  uintptr_t, size_t;
#pragma region std::forward
	template <class _Ty>
	struct remove_reference {
		using type = _Ty;
		using _Const_thru_ref_type = const _Ty;
	};
	template <class _Ty>
	using remove_reference_t = typename remove_reference<_Ty>::type;

	template <class>
	constexpr bool is_lvalue_reference_v = false; // determine whether type argument is an lvalue reference

	template <class _Ty>
	constexpr bool is_lvalue_reference_v<_Ty&> = true;

	template <class _Ty>
	constexpr _Ty&& forward(
		remove_reference_t<_Ty>& _Arg) noexcept { // forward an lvalue as either an lvalue or an rvalue
		return static_cast<_Ty&&>(_Arg);
	}

	template <class _Ty>
	constexpr _Ty&& forward(remove_reference_t<_Ty>&& _Arg) noexcept { // forward an rvalue as an rvalue
		static_assert(!is_lvalue_reference_v<_Ty>, "bad forward call");
		return static_cast<_Ty&&>(_Arg);
	}
#pragma endregion 

#else
	using namespace std;
#endif

}


namespace CallSpoofer
{
	class SpoofFunction
	{
	public:
		uintptr_t temp = 0;
		const uintptr_t xor_key = 0xff00ff00ff00ff00;
		void* ret_addr_in_stack = 0;

		SpoofFunction(void* addr) :ret_addr_in_stack(addr)
		{
			temp = *(uintptr_t*)ret_addr_in_stack;
			temp ^= xor_key;
			*(uintptr_t*)ret_addr_in_stack = 0;
		}
		~SpoofFunction()
		{
			temp ^= xor_key;
			*(uintptr_t*)ret_addr_in_stack = temp;
		}
	};

#ifdef _KERNEL_MODE
	__forceinline PVOID LocateShellCode(PVOID func, size_t size = 500)
	{
		void* addr = ExAllocatePoolWithTag(NonPagedPool, size, (ULONG)"File");
		if (!addr)
			return nullptr;
		return memcpy(addr, func, size);
	}
#else
	__forceinline PVOID LocateShellCode(PVOID func, size_t size = SHELLCODE_GENERATOR_SIZE)
	{
		void* addr = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!addr)
			return nullptr;
		return memcpy(addr, func, size);
	}
#endif

#ifdef _KERNEL_MODE
	template <typename RetType, typename Func, typename ...Args>
	RetType
#else
	template <typename Func, typename ...Args>
	typename std::invoke_result<Func, Args...>::type
#endif
		__declspec(safebuffers)ShellCodeGenerator(Func f, Args&... args)
	{
#ifdef _KERNEL_MODE
		using this_func_type = decltype(ShellCodeGenerator<RetType, Func, Args&...>);
		using return_type = RetType;
#else
		using this_func_type = decltype(ShellCodeGenerator<Func, Args&...>);
		using return_type = typename std::invoke_result<Func, Args...>::type;
#endif
		const uintptr_t xor_key = 0xff00ff00ff00ff00;
		void* ret_addr_in_stack = _AddressOfReturnAddress();
		uintptr_t temp = *(uintptr_t*)ret_addr_in_stack;
		temp ^= xor_key;
		*(uintptr_t*)ret_addr_in_stack = 0;

		if constexpr (std::is_same<return_type, void>::value)
		{
			f(args...);
			temp ^= xor_key;
			*(uintptr_t*)ret_addr_in_stack = temp;
		}
		else
		{
			return_type&& ret = f(args...);
			temp ^= xor_key;
			*(uintptr_t*)ret_addr_in_stack = temp;
			return ret;
		}
	}



#ifdef _KERNEL_MODE
	template<typename RetType, class Func>
#else
	template<class Func >
#endif
	class SafeCall
	{

		Func* funcPtr;

	public:
		SafeCall(Func* func) :funcPtr(func) {}


		template<typename... Args>
		__forceinline decltype(auto) operator()(Args&&... args)
		{
			SPOOF_FUNC;

#ifdef _KERNEL_MODE
			using return_type = RetType;
			using p_shell_code_generator_type = decltype(&ShellCodeGenerator<RetType, Func*, Args...>);
			PVOID self_addr = static_cast<PVOID>(&ShellCodeGenerator<RetType, Func*, Args&&...>);
#else	
			using return_type = typename std::invoke_result<Func, Args...>::type;
			using p_shell_code_generator_type = decltype(&ShellCodeGenerator<Func*, Args...>);
			p_shell_code_generator_type self_addr = static_cast<p_shell_code_generator_type>(&ShellCodeGenerator<Func*, Args&&...>);
#endif

			p_shell_code_generator_type p_shellcode{};

			static size_t count{};
			static p_shell_code_generator_type orig_generator[MAX_FUNC_BUFFERED]{};
			static p_shell_code_generator_type alloc_generator[MAX_FUNC_BUFFERED]{};

			unsigned index{};
			while (orig_generator[index])
			{
				if (orig_generator[index] == self_addr)
				{
#ifdef _KERNEL_MODE
					//DbgPrint("Found allocated generator");
#else
					//std::cout << "Found allocated generator" << std::endl;
#endif

					p_shellcode = alloc_generator[index];
					break;
				}
				index++;
			}

			if (!p_shellcode)
			{
#ifdef _KERNEL_MODE
				//DbgPrint("Alloc generator");
#else	
				//std::cout << "Alloc generator" << std::endl;
#endif

				p_shellcode = reinterpret_cast<p_shell_code_generator_type>( LocateShellCode(self_addr));
				orig_generator[count] = self_addr;
				alloc_generator[count] = p_shellcode;
				count++;
			}

			if (!p_shellcode)
			{
				//DbgPrint("!p_shellcode");
			}

			return p_shellcode(funcPtr, args...);
		}
	};
}
