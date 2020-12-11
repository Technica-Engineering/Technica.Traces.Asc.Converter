/*
  Copyright (c) 2020 Technica Engineering GmbH
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/
#include <array>
#include <codecvt>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <locale>
#include <map>

#include <Vector/ASC.h>
#include <light_pcapng_ext.h>
#include "endianness.h"

using namespace Vector::ASC;

#define HAS_FLAG(var,pos) ((var) & (1<<(pos)))
#define NANOS_PER_SEC 1000000000
#define LINKTYPE_ETHERNET 1 
#define LINKTYPE_CAN_SOCKETCAN 227 

#define DIR_IN    1
#define DIR_OUT   2

class CanFrame {
private:
	uint8_t raw[72] = { 0 };
public:

	uint32_t id() {
		return ntoh32(*(uint32_t*)raw) & 0x1fffffff;
	}

	void id(uint32_t value) {
		uint8_t id_flags = *raw & 0xE0;
		*(uint32_t*)raw = hton32(value);
		*raw |= id_flags;
	}

	bool ext() {
		return (*raw & 0x80) != 0;
	}
	void ext(bool value) {
		uint8_t masked = *raw & 0x7F;
		*raw = masked | value << 7;
	}

	bool rtr() {
		return (*raw & 0x40) != 0;
	}
	void rtr(bool value) {
		uint8_t masked = *raw & 0xBF;
		*raw = masked | value << 6;
	}

	bool err() {
		return (*raw & 0x20) != 0;
	}
	void err(bool value) {
		uint8_t masked = *raw & 0xDF;
		*raw = masked | value << 5;
	}

	bool brs() {
		return (*(raw + 5) & 0x01) != 0;
	}
	void brs(bool value) {
		uint8_t masked = *(raw + 5) & 0xFE;
		*(raw + 5) = masked | value << 0;
	}

	bool esi() {
		return (*(raw + 5) & 0x02) != 0;
	}
	void esi(bool value) {
		uint8_t masked = *(raw + 5) & 0xFD;
		*(raw + 5) = masked | value << 1;
	}

	uint8_t len() {
		return *(raw + 4);
	}
	void len(uint8_t value) {
		*(raw + 4) = value;
	}

	const uint8_t* data() {
		return raw + 8;
	}
	void data(const uint8_t* value, size_t size) {
		memcpy(raw + 8, value, size);
	}

	const uint8_t* bytes() {
		return raw;
	}

	const uint8_t size() {
		return len() + 8;
	}

};
uint64_t get_offset_from_file_date(tm file_date) {
	time_t time = mktime(&file_date);
	return time;
}
template <class ObjHeader>
int write_packet(
	light_pcapng pcapng,
	uint16_t link_type,
	ObjHeader* oh,
	uint32_t length,
	const uint8_t* data,
	uint64_t date_offset,
	uint32_t flags = 0
) {

	light_packet_interface interface = { 0 };
	interface.link_type = link_type;
	interface.name = (char*)std::to_string(oh->channel).c_str();
	interface.description = "";
	interface.timestamp_resolution = NANOS_PER_SEC;

	light_packet_header header = { 0 };
	uint64_t ts = (uint64_t)(oh->time * (EthTime)NANOS_PER_SEC) + date_offset * NANOS_PER_SEC;
	header.timestamp.tv_sec = ts / NANOS_PER_SEC;
	header.timestamp.tv_nsec = ts % NANOS_PER_SEC;

	header.captured_length = length;
	header.original_length = length;

	return light_write_packet(pcapng, &interface, &header, data);
}

// CAN_MESSAGE = 20
void write(light_pcapng outfile, CanMessage* obj, uint64_t date_offset) {
	CanFrame can;

	can.id(obj->id);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// CAN_EXTENDED_MESSAGE = 21
void write(light_pcapng outfile, CanExtendedMessage* obj, uint64_t date_offset) {
	CanFrame can;
	can.ext(true);
	can.id(obj->id);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// CAN_REMOTE_FRAME = 22
void write(light_pcapng outfile, CanRemoteFrame* obj, uint64_t date_offset) {
	CanFrame can;

	can.id(obj->id);

	can.rtr(true);

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// CAN_ERROR_FRAME = 23
void write(light_pcapng outfile, CanErrorFrame* obj, uint64_t date_offset) {
	CanFrame can;

	can.id(obj->id);
	can.len(8);
	can.err(true);

	uint32_t flags = DIR_IN;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// CAN_ERROR = 25
void write(light_pcapng outfile, CanError* obj, uint64_t date_offset) {
	CanFrame can;

	can.len(8);
	can.err(true);

	uint32_t flags = obj->rxErr != 0 ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// CAN_OVERLOAD_FRAME = 26
void write(light_pcapng outfile, CanOverloadFrame* obj, uint64_t date_offset) {
	CanFrame can;

	can.err(true);

	uint32_t flags = DIR_IN;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// CAN_FD_MESSAGE = 30
void write(light_pcapng outfile, CanFdMessage* obj, uint64_t date_offset) {
	CanFrame can;
	can.id(obj->id);
	can.esi(obj->esi);
	can.rtr(HAS_FLAG(obj->flags, 7));
	can.brs(obj->brs);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// CAN_FD_EXTENDED_MESSAGE = 32
void write(light_pcapng outfile, CanFdExtendedMessage* obj, uint64_t date_offset) {
	CanFrame can;
	can.ext(true);
	can.id(obj->id);
	can.esi(obj->esi);
	can.rtr(HAS_FLAG(obj->flags, 7));
	can.brs(obj->brs);
	can.len(obj->dlc);
	can.data(obj->data.data(), obj->data.size());

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// CAN_FD_ERROR_FRAME = 33
void write(light_pcapng outfile, CanFdErrorFrame* obj, uint64_t date_offset) {
	CanFrame can;
	can.err(true);
	can.esi(obj->esi);
	can.rtr(HAS_FLAG(obj->flags1, 7));
	can.brs(obj->brs);
	can.len(8);

	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_CAN_SOCKETCAN, obj, can.size(), can.bytes(), date_offset, flags);
}

// ETHERNET_PACKET = 110
void write(light_pcapng outfile, EthernetPacket* obj, uint64_t date_offset) {
	std::vector<uint8_t> eth(obj->data);
	uint32_t flags = obj->dir == Dir::Rx ? DIR_IN : DIR_OUT;

	write_packet(outfile, LINKTYPE_ETHERNET, obj, (uint32_t)eth.size(), eth.data(), date_offset, flags);
}
// ETHERNET_RX_ERROR
void write(light_pcapng outfile, EthernetRxError* obj, uint64_t date_offset) {
	std::vector<uint8_t> eth(obj->data);

	uint8_t* crcPtr = (uint8_t*)&obj->frameChecksum;
	std::vector<uint8_t> crc(crcPtr, crcPtr + 4);
	eth.insert(eth.end(), crc.begin(), crc.end());

	uint32_t flags = DIR_IN;

	write_packet(outfile, LINKTYPE_ETHERNET, obj, (uint32_t)eth.size(), eth.data(), date_offset, flags);
}

// FILEDATE
uint64_t calculate_filedate(FileDate *fd) {
	time_t t = mktime(&(fd->date));
	return t;
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		fprintf(stderr, "Usage %s [infile] [outfile]\n", argv[0]);
		return 1;
	}
	Vector::ASC::File infile;
	Vector::ASC::FileDate* fd = NULL;

	infile.open(argv[1]);
	if (!infile.is_open()) {
		fprintf(stderr, "Unable to open: %s\n", argv[1]);
		return 1;
	}
	light_pcapng outfile = light_pcapng_open(argv[2], "wb");
	if (!outfile) {
		fprintf(stderr, "Unable to open: %s\n", argv[2]);
		return 1;
	}
	uint64_t file_date = 0;
	while (!infile.eof()) {
		Event* ohb = nullptr;

		/* read and capture exceptions, e.g. unfinished files */
		try {
			ohb = infile.read();
		}
		catch (std::exception& e) {
			std::cout << "Exception: " << e.what() << std::endl;
		}
		if (ohb == nullptr) {
			break;
		}
		/* Object */
		switch (ohb->eventType) {
		case Event::EventType::CanMessage:
			write(outfile, reinterpret_cast<CanMessage*>(ohb), file_date);
			break;
		case Event::EventType::CanExtendedMessage:
			write(outfile, reinterpret_cast<CanExtendedMessage*>(ohb), file_date);
			break;
		case Event::EventType::CanRemoteFrame:
			write(outfile, reinterpret_cast<CanRemoteFrame*>(ohb), file_date);
			break;
		case Event::EventType::CanErrorFrame:
			write(outfile, reinterpret_cast<CanErrorFrame*>(ohb), file_date);
			break;
		case Event::EventType::CanError:
			write(outfile, reinterpret_cast<CanError*>(ohb), file_date);
			break;
		case Event::EventType::CanOverloadFrame:
			write(outfile, reinterpret_cast<CanOverloadFrame*>(ohb), file_date);
			break;
		case Event::EventType::CanFdMessage:
			write(outfile, reinterpret_cast<CanFdMessage*>(ohb), file_date);
			break;
		case Event::EventType::CanFdExtendedMessage:
			write(outfile, reinterpret_cast<CanFdExtendedMessage*>(ohb), file_date);
			break;
		case Event::EventType::CanFdErrorFrame:
			write(outfile, reinterpret_cast<CanFdErrorFrame*>(ohb), file_date);
			break;
		case Event::EventType::EthernetPacket:
			write(outfile, reinterpret_cast<EthernetPacket*>(ohb), file_date);
			break;
		case Event::EventType::EthernetRxError:
			write(outfile, reinterpret_cast<EthernetRxError*>(ohb), file_date);
			break;
		case Event::EventType::FileDate:
			file_date = calculate_filedate(reinterpret_cast<FileDate*>(ohb));
			break;
		}
	}
}
