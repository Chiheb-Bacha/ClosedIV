#include "main.h"

void(*LoadMpDlc)();
void(*EnableMpDlcMaps)(bool);

memory gameStateAddr(0, false);
const int GAME_STATE_PLAYING = 0;

bool(*GameStateChangeOrig)(int);
bool GameStateChangeHook(int gameState)
{
	if (gameState == GAME_STATE_PLAYING)
	{
		LoadMpDlc();
		EnableMpDlcMaps(true);
	}
	return GameStateChangeOrig(gameState);
}

void EnableMpDlcAndSetGameState() {
	// Calling these crashes the game, might get back to this, but it's not that important for the tool
	//LoadMpDlc();
	//EnableMpDlcMaps(true);
	gameStateAddr.put<int>(GAME_STATE_PLAYING); // This is just a trampoline for the same instruction that we overwrite
}

static memory::InitFuncs EnableMpDlcMapsHooks([] {
	// get game state to enable mp dlc maps
	if (config::get_config<bool>("dlcmaps"))
	{
		if (IsEnhanced()) {
			auto mem = memory::scan("a8 01 0f 85 ? ? ? ? 83 3d ? ? ? ? ? 74");
			gameStateAddr = mem.add(10).rip().add(1); // instruction is a cmp with 0

			// Using EasyHook and nasm for this is probably the move, now it crashes...
			mem.add(17).set_call(EnableMpDlcAndSetGameState);
			mem.add(17).add(5).nop(5);

			mem = memory::scan("c6 05 ? ? ? ? 01 b1 01 e8 ? ? ? ? 83 3d ? ? ? ? ? 74");
			mem.add(23).set_call(EnableMpDlcAndSetGameState);
			mem.add(23).add(5).nop(5);
		}
		else {
			auto mem = memory::scan("E8 ? ? ? ? 84 C0 74 ? E8 ? ? ? ? 0F B6 0D");
			GameStateChangeOrig = mem.add(1).rip().as<decltype(GameStateChangeOrig)>();
			mem.set_call(GameStateChangeHook);
		}

		LoadMpDlc = IsEnhanced() ? memory::scan("56 48 83 ec 20 c6 05 ? ? ? ? 00 48 8d 35 ? ? ? ? 48 89 f1 e9").as<decltype(LoadMpDlc)>() :
			memory::scan("C6 05 ? ? ? ? 00 E8 ? ? ? ? 48 8B 0D ? ? ? ? BA E2 99 8F 57").add(-0xB).as<decltype(LoadMpDlc)>();

		EnableMpDlcMaps = IsEnhanced() ? memory::scan("56 48 83 ec ? 89 ce 89 0d").as<decltype(EnableMpDlcMaps)>() :
			memory::scan("40 53 48 83 EC 20 8B D9 89 0D").as<decltype(EnableMpDlcMaps)>();
	}
});