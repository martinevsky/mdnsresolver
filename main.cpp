#include <iostream>
#include <sstream>
#include <string>

#include <boost/range.hpp>
#include <boost/range/algorithm/copy.hpp>

#include <boost/algorithm/string/finder.hpp>
#include <boost/algorithm/string/find_iterator.hpp>
#include <boost/algorithm/string/classification.hpp>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

//© https://en.wikipedia.org/wiki/Multicast_DNS
const uint8_t g_header[] =
{
	0x00, 0x00,                                                   // Transaction ID
	0x00, 0x00,                                                   // Flags
	0x00, 0x01,                                                   // Number of questions
	0x00, 0x00,                                                   // Number of answers
	0x00, 0x00,                                                   // Number of authority resource records
	0x00, 0x00,                                                   // Number of additional resource records
};

// 0x0B, 'r', 'a', 's', 'p', 'b', 'e', 'r', 'r', 'y', 'p', 'i',   // "raspberrypi"
// 0x05, 'l', 'o', 'c', 'a', 'l',                                 // "local"

const uint8_t g_footer[] =
{
	0x00,                                                         // Terminator
	0x00, 0x01,                                                   // Type (A record)
	0x00, 0x01                                                    // Class
};

class Sender
{
public:
	Sender (boost::asio::io_service& io_service, const char* n): 
		m_endpoint (boost::asio::ip::address::from_string ("224.0.0.251"), 5353),
		m_socket (io_service, m_endpoint.protocol()),
		m_timer (io_service)
	{
		const auto name = boost::as_literal (n);
															//   \/ - for one subpart size
		m_message.reserve (boost::size (g_header) + name.size() + 1 + boost::size (g_footer));
		auto out = std::back_inserter (m_message);
		boost::range::copy (boost::make_iterator_range (g_header), out);

		const auto beg = boost::make_split_iterator (name, boost::token_finder (boost::is_any_of (".")));
		for (const auto sub : boost::make_iterator_range (beg, decltype (beg)()))
		{
			if (sub.size() > 0xFF)
				throw std::runtime_error ("Too long sub");

			*out = static_cast<uint8_t> (sub.size());
			++out;

			boost::range::copy (sub, out);
		}

		boost::range::copy (boost::make_iterator_range (g_footer), out);

		m_socket.async_send_to (
			boost::asio::buffer (m_message), m_endpoint,
			boost::bind(&Sender::handle_send_to, this,
				boost::asio::placeholders::error));

		m_socket.async_receive_from (
			boost::asio::buffer (m_responce), m_receivedFrom,
			boost::bind (&Sender::handle_receive_from, this,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));

		m_timer.expires_from_now (boost::posix_time::seconds (10));
		m_timer.async_wait (
			boost::bind (&Sender::handle_timeout, this,
				boost::asio::placeholders::error));
	}

	void handle_send_to (const boost::system::error_code& error)
	{
		if (error)
			throw boost::system::system_error (error);
	}

	void handle_timeout (const boost::system::error_code& error)
	{
		if (!error)
			throw std::runtime_error ("Timeout");
	}

	void handle_receive_from (const boost::system::error_code& error, size_t /*bytes_recvd*/)
	{
		if (!error)
		{
			m_timer.cancel();
			// Here we can parse received packet to get IP. Or... Simple out endpoint address, what sends it )
			std::cout << m_receivedFrom.address() << std::endl;
		}
		else
		{
			throw boost::system::system_error (error);
		}
	}

private:
	boost::asio::ip::udp::endpoint m_endpoint;
	boost::asio::ip::udp::socket   m_socket;
	boost::asio::deadline_timer    m_timer;

	std::vector<uint8_t>           m_message;
	uint8_t                        m_responce[1024];
	boost::asio::ip::udp::endpoint m_receivedFrom;
};

int main (int argc, char* argv[])
{
	try
	{
		if (argc != 2)
		{
			std::cerr << "Usage: mDNSResolver raspberrypi.local";
			return 1;
		}

		boost::asio::io_service io_service;
		Sender sender (io_service, argv[1]);
		io_service.run();

		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what();
		return 1;
	}
}