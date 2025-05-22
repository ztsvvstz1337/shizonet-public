
#ifdef ARDUINO
#include <shizonet.h>
#include <shz_script.h>
#else
#include "shizonet.h"
#include <shz_script.h>
#endif

#undef min

static void parse_key_value(byte* read_data, size_t read_size, shzvar* var)
{
	shznet_kv_reader r(read_data, read_size);
	auto jh = var->get_json();
	jh->clear();
	while (r.read())
	{
		auto param_data = jh->get_key(r.get_key());
		auto data = r.get_value();
		auto size = r.get_value_size();

		switch (r.get_fmt())
		{
		case SHZNET_PKT_FMT_DATA:
			param_data->get_uchar_array()->resize(size);
			memcpy(param_data->get_uchar_array()->data(), data, size);
			break;
		case SHZNET_PKT_FMT_STRING:
			param_data->changetype(SHZVAR_STRING);
			if (size)
				param_data->VarPtr.strptr->assign((char*)data, size - 1);
			else
				*param_data->VarPtr.strptr = "";
			break;
		case SHZNET_PKT_FMT_JSON:
			param_data->get_json()->from_data(data, size);
			break;
		case SHZNET_PKT_FMT_KEY_VALUE:
			parse_key_value(data, size, param_data);
			break;
		case SHZNET_PKT_FMT_INT16:
			param_data->initInt(*(int16_t*)data);
			break;
		case SHZNET_PKT_FMT_INT32:
			param_data->initInt(*(int32_t*)data);
			break;
		case SHZNET_PKT_FMT_INT64:
			param_data->initInt(*(int64_t*)data);
			break;
		case SHZNET_PKT_FMT_FLOAT32:
			param_data->initFloat(*(float*)data);
			break;
		case SHZNET_PKT_FMT_FLOAT64:
			param_data->initFloat(*(double*)data);
			break;
		case SHZNET_PKT_FMT_INT16_ARRAY:
		{
			auto set = param_data->getIntset();
			auto small_size = size / sizeof(int16_t);
			set->resize(small_size);
			for (size_t i = 0; i < small_size; i++)
			{
				set->data()[i] = ((int16_t*)&data)[i];
			}
			break;
		}
		case SHZNET_PKT_FMT_INT32_ARRAY:
		{
			auto set = param_data->getIntset();
			set->resize(size / sizeof(int));
			memcpy(set->data(), data, set->size() * sizeof(int));
			break;
		}
		case SHZNET_PKT_FMT_INT64_ARRAY:
		{
			auto set = param_data->getBigintset();
			set->resize(size / sizeof(long long));
			memcpy(set->data(), data, set->size() * sizeof(long long));
			break;
		}
		case SHZNET_PKT_FMT_FLOAT32_ARRAY:
		{
			auto set = param_data->getFloatset();
			set->resize(size / sizeof(float));
			memcpy(set->data(), data, set->size() * sizeof(float));
			break;
		}
		case SHZNET_PKT_FMT_FLOAT64_ARRAY:
		{
			auto set = param_data->getDoubleset();
			set->resize(size / sizeof(double));
			memcpy(set->data(), data, set->size() * sizeof(double));
			break;
		}
		default:
			break;
		}
	}
}

static void data_to_var(shznet_pkt_dataformat fmt, byte* data, size_t size, shzvar* var)
{
	auto param_data = var;
	switch (fmt)
	{
	case SHZNET_PKT_FMT_DATA:
		param_data->get_uchar_array()->resize(size);
		memcpy(param_data->get_uchar_array()->data(), data, size);
		break;
	case SHZNET_PKT_FMT_STRING:
		param_data->changetype(SHZVAR_STRING);
		param_data->VarPtr.strptr->assign((char*)data, size);
		break;
	case SHZNET_PKT_FMT_JSON:
		param_data->get_json()->from_data(data, size);
		break;
	case SHZNET_PKT_FMT_KEY_VALUE:
		parse_key_value(data, size, param_data);
		break;
	case SHZNET_PKT_FMT_INT16:
		param_data->initInt(*(int16_t*)data);
		break;
	case SHZNET_PKT_FMT_INT32:
		param_data->initInt(*(int32_t*)data);
		break;
	case SHZNET_PKT_FMT_INT64:
		param_data->initInt(*(int64_t*)data);
		break;
	case SHZNET_PKT_FMT_FLOAT32:
		param_data->initFloat(*(float*)data);
		break;
	case SHZNET_PKT_FMT_FLOAT64:
		param_data->initFloat(*(double*)data);
		break;
	case SHZNET_PKT_FMT_INT16_ARRAY:
	{
		auto set = param_data->getIntset();
		auto small_size = size / sizeof(int16_t);
		set->resize(small_size);
		for (size_t i = 0; i < small_size; i++)
		{
			set->data()[i] = *(int16_t*)&data[i * sizeof(int16_t)];
		}
		break;
	}
	case SHZNET_PKT_FMT_INT32_ARRAY:
	{
		auto set = param_data->getIntset();
		set->resize(size / sizeof(int));
		memcpy(set->data(), data, set->size() * sizeof(int32_t));
		break;
	}
	case SHZNET_PKT_FMT_INT64_ARRAY:
	{
		auto set = param_data->getBigintset();
		set->resize(size / sizeof(long long));
		memcpy(set->data(), data, set->size() * sizeof(int64_t));
		break;
	}
	case SHZNET_PKT_FMT_FLOAT32_ARRAY:
	{
		auto set = param_data->getFloatset();
		set->resize(size / sizeof(float));
		memcpy(set->data(), data, set->size() * sizeof(float));
		break;
	}
	case SHZNET_PKT_FMT_FLOAT64_ARRAY:
	{
		auto set = param_data->getDoubleset();
		set->resize(size / sizeof(double));
		memcpy(set->data(), data, set->size() * sizeof(double));
		break;
	}
	default:
		return;
	}
}

static shznet_ticketid var_to_device(const char* cmd, shzvar* var, shznet_device* device, bool sequential, uint64_t timeout)
{
	shznet_ticketid send_id = -1;

	switch (var->Type)
	{
	case SHZVAR_INT:
	{
		int64_t v = var->get_int();
		send_id = (device->send_reliable(cmd,
			(byte*)&v,
			sizeof(int64_t),
			SHZNET_PKT_FMT_INT64, sequential, timeout));
		break;
	}
	case SHZVAR_FLOAT:
	{
		double v = var->get_float();
		send_id = (device->send_reliable(cmd,
			(byte*)&v,
			sizeof(double),
			SHZNET_PKT_FMT_FLOAT64, sequential, timeout));
		break;
	}
	case SHZVAR_STRING:
		send_id = (device->send_reliable(cmd,
			(byte*)var->VarPtr.strptr->c_str(),
			var->VarPtr.strptr->length(),
			SHZNET_PKT_FMT_STRING, sequential, timeout));
		break;
		/*case SHZVAR_shzobject:
		{
			SOH_Instance()->
			auto obj = SOH_Instance()->get_object(var);
			if(obj)
				obj->
			break;
		}*/
	case SHZVAR_JSON:
	{
		auto jh = var->get_json();
		static uchar_array_s _tmp;
		_tmp.clear();
		jh->to_data(_tmp);

		send_id = (device->send_reliable(cmd,
			(byte*)_tmp.data(),
			_tmp.size(),
			SHZNET_PKT_FMT_JSON, sequential, timeout));
		break;
	}
	case SHZVAR_CHAR_ARRAY:
	case SHZVAR_UCHAR_ARRAY:
		send_id = (device->send_reliable(cmd,
			(byte*)var->get_uchar_array()->data(),
			var->get_uchar_array()->size(),
			SHZNET_PKT_FMT_DATA, sequential, timeout));
		break;
	case SHZVAR_FLOAT_ARRAY:
		send_id = (device->send_reliable(cmd,
			(byte*)var->getFloatset()->data(),
			var->getFloatset()->size() * sizeof(float),
			SHZNET_PKT_FMT_FLOAT32_ARRAY, sequential, timeout));
		break;
	case SHZVAR_DOUBLE_ARRAY:
		send_id = (device->send_reliable(cmd,
			(byte*)var->getDoubleset()->data(),
			var->getFloatset()->size() * sizeof(double),
			SHZNET_PKT_FMT_FLOAT64_ARRAY, sequential, timeout));
		break;
	case SHZVAR_INT_ARRAY:
		send_id = (device->send_reliable(cmd,
			(byte*)var->getIntset()->data(),
			var->getIntset()->size() * sizeof(int),
			SHZNET_PKT_FMT_INT32_ARRAY, sequential, timeout));
		break;
	case SHZVAR_LONG_ARRAY:
		send_id = (device->send_reliable(cmd,
			(byte*)var->getBigintset()->data(),
			var->getBigintset()->size() * sizeof(long long),
			SHZNET_PKT_FMT_INT64_ARRAY, sequential, timeout));
		break;
	default:
		SLH_Instance()->logerror("invalid data type in send_fast!");
		break;
	}

	return send_id;
}

static void var_to_responder(shzvar* var, std::shared_ptr<shznet_responder>& responder)
{
	switch (var->Type)
	{
	case SHZVAR_INT:
	{
		int64_t v = var->get_int();
		responder->respond(
			(byte*)&v,
			sizeof(int64_t),
			SHZNET_PKT_FMT_INT64);
		break;
	}
	case SHZVAR_FLOAT:
	{
		double v = var->get_float();
		responder->respond(
			(byte*)&v,
			sizeof(double),
			SHZNET_PKT_FMT_FLOAT64);
		break;
	}
	case SHZVAR_STRING:
		responder->respond(
			(byte*)var->VarPtr.strptr->c_str(),
			var->VarPtr.strptr->length(),
			SHZNET_PKT_FMT_STRING);
		break;
		/*case SHZVAR_shzobject:
		{
			SOH_Instance()->
			auto obj = SOH_Instance()->get_object(var);
			if(obj)
				obj->
			break;
		}*/
	case SHZVAR_JSON:
	{
		auto jh = var->get_json();
		static uchar_array_s _tmp;
		_tmp.clear();
		jh->to_data(_tmp);

		responder->respond(
			(byte*)_tmp.data(),
			_tmp.size(),
			SHZNET_PKT_FMT_JSON);
		break;
	}
	case SHZVAR_CHAR_ARRAY:
	case SHZVAR_UCHAR_ARRAY:
		responder->respond(
			(byte*)var->get_uchar_array()->data(),
			var->get_uchar_array()->size(),
			SHZNET_PKT_FMT_DATA);
		break;
	case SHZVAR_FLOAT_ARRAY:
		responder->respond(
			(byte*)var->getFloatset()->data(),
			var->getFloatset()->size() * sizeof(float),
			SHZNET_PKT_FMT_FLOAT32_ARRAY);
		break;
	case SHZVAR_DOUBLE_ARRAY:
		responder->respond(
			(byte*)var->getDoubleset()->data(),
			var->getFloatset()->size() * sizeof(double),
			SHZNET_PKT_FMT_FLOAT64_ARRAY);
		break;
	case SHZVAR_INT_ARRAY:
		responder->respond(
			(byte*)var->getIntset()->data(),
			var->getIntset()->size() * sizeof(int),
			SHZNET_PKT_FMT_INT32_ARRAY);
		break;
	case SHZVAR_LONG_ARRAY:
		responder->respond(
			(byte*)var->getBigintset()->data(),
			var->getBigintset()->size() * sizeof(long long),
			SHZNET_PKT_FMT_INT64_ARRAY);
		break;
	default:
		SLH_Instance()->logerror("invalid data type in send_fast!");
		break;
	}
}

class ShizoNetDevice : public shzobject_ext<ShizoNetDevice>
{
	SHZOBJECT_DECLARE(ShizoNetDevice);

	shznet_device_ptr m_device;

	uint64_t current_uid = 0;

public:
	ShizoNetDevice(shznet_device_ptr dev = 0)
	{
		m_device = dev;
		if(m_device)
			current_uid = m_device->get_unique_id();
	}
	virtual ~ShizoNetDevice()
	{

	}
	virtual void free() override
	{
		//printf("shznet device free\n");
		delete this;
	}

	static void scriptRegister()
	{
		//legacy functions, remove someday
		scriptFunction("is_shizonet", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{			
				result.initInt(1);
			}, 0, true, false, "()");
		scriptFunction("is_artnet", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.initInt(0);
			}, 0, true, false, "()");

		scriptFunction("start_logging", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initInt(0);  return; }
				obj->m_device->send_get("debug_log");
				result.initInt(0);
			}, 0, true, false, "()");

		scriptFunction("stop_logging", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initInt(0);  return; }
				obj->m_device->send_get("debug_log_stop");
				result.initInt(0);
			}, 0, true, false, "()");

		scriptFunction("get_name", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initString("");  return; }
				result.initString(obj->m_device->get_name().c_str());
			}, 0, true, false, "()");
		scriptFunction("get_mac", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initString("");  return; }
				result.initString(obj->m_device->get_mac().str().c_str());
			}, 0, true, false, "()");
		scriptFunction("get_ip", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initString("");  return; }
				result.initString(obj->m_device->get_ip().str().c_str());
			}, 0, true, false, "()");
		
		scriptFunction("still_valid", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initInt(0);  return; }
				result.initInt(obj->m_device->valid() && obj->m_device->get_unique_id() == obj->current_uid);
			}, 0, true, false, "() check if device is still online or if it is offline or has reconnected by the time (new session or invalid session)");
		scriptFunction("online", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initInt(0);  return; }
				result.initInt(obj->m_device->online() && obj->m_device->get_unique_id() == obj->current_uid);
			}, 0, true, false, "() check if device is still online or if it is offline or has reconnected by the time (new session or invalid session)");

		scriptFunction("send_fast", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.initInt(0);

				if (!obj->m_device) { return; }

				if (params.size() < 1)
					return;
				if (params[0]->Type != SHZVAR_STRING)
					return;

				auto dtype = params[1]->Type;

				const char* cmd = params[0]->VarPtr.strptr->c_str();

				switch (dtype)
				{
				case SHZVAR_INT:
				{
					int64_t v = params[1]->get_int();
					if (obj->m_device->send_unreliable(cmd,
						(byte*)&v,
						sizeof(int64_t),
						SHZNET_PKT_FMT_INT64))
						result.initInt(1);
					break;
				}
				case SHZVAR_FLOAT:
				{
					double v = params[1]->get_float();
					if (obj->m_device->send_unreliable(cmd,
						(byte*)&v,
						sizeof(double),
						SHZNET_PKT_FMT_FLOAT64))
						result.initInt(1);
					break;
				}
				case SHZVAR_STRING:
					if (obj->m_device->send_unreliable(cmd,
						(byte*)params[1]->VarPtr.strptr->c_str(),
						params[1]->VarPtr.strptr->length(),
						SHZNET_PKT_FMT_STRING))
						result.initInt(1);
					break;
					/*case SHZVAR_shzobject:
					{
						SOH_Instance()->
						auto obj = SOH_Instance()->get_object(params[1]);
						if(obj)
							obj->
						break;
					}*/
				case SHZVAR_JSON:
				{
					auto jh = params[1]->get_json();
					static uchar_array_s _tmp;
					_tmp.clear();
					jh->to_data(_tmp);

					if (obj->m_device->send_unreliable(cmd,
						(byte*)_tmp.data(),
						_tmp.size(),
						SHZNET_PKT_FMT_JSON))
						result.initInt(1);
					break;
				}
				case SHZVAR_CHAR_ARRAY:
				case SHZVAR_UCHAR_ARRAY:
					if (obj->m_device->send_unreliable(cmd,
						(byte*)params[1]->get_uchar_array()->data(),
						params[1]->get_uchar_array()->size(),
						SHZNET_PKT_FMT_DATA))
						result.initInt(1);
					break;
				case SHZVAR_FLOAT_ARRAY:
					if (obj->m_device->send_unreliable(cmd,
						(byte*)params[1]->getFloatset()->data(),
						params[1]->getFloatset()->size() * sizeof(float),
						SHZNET_PKT_FMT_FLOAT32_ARRAY))
						result.initInt(1);
					break;
				case SHZVAR_DOUBLE_ARRAY:
					if (obj->m_device->send_unreliable(cmd,
						(byte*)params[1]->getDoubleset()->data(),
						params[1]->getFloatset()->size() * sizeof(double),
						SHZNET_PKT_FMT_FLOAT64_ARRAY))
						result.initInt(1);
					break;
				case SHZVAR_INT_ARRAY:
					if (obj->m_device->send_unreliable(cmd,
						(byte*)params[1]->getIntset()->data(),
						params[1]->getIntset()->size() * sizeof(int),
						SHZNET_PKT_FMT_INT32_ARRAY))
						result.initInt(1);
					break;
				case SHZVAR_LONG_ARRAY:
					if (obj->m_device->send_unreliable(cmd,
						(byte*)params[1]->getBigintset()->data(),
						params[1]->getBigintset()->size() * sizeof(long long),
						SHZNET_PKT_FMT_INT64_ARRAY))
						result.initInt(1);
					break;
				default:
					SLH_Instance()->logerror("invalid data type in send_fast!");
					break;
				}
			}, 2, true, false, "(cmd, data)");

		scriptFunction("send", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.initInt(0);

				if (!obj->m_device) { return; }

				if (params.size() < 1)
					return;
				if (params[0]->Type != SHZVAR_STRING)
					return;

				auto dtype = params[1]->Type;

				const char* cmd = params[0]->VarPtr.strptr->c_str();

				bool sequential = params.size() >= 3 ? params[2]->get_int() : true;
				int64_s timeout = params.size() >= 4 ? params[3]->get_int() : -1;

				shznet_ticketid send_id = var_to_device(cmd, params[1], obj->m_device.get(), sequential, timeout);
				
				bool wait_finish = params.size() >= 5 ? params[4]->get_int() : false;

				if (wait_finish && send_id != INVALID_TICKETID)
				{
					shzptr blk_ref(blk);
					if (!obj->m_device->send_finished(send_id, [blk_ref, &result](bool success)
						{
							if (!blk_ref.get())
								return;

							result.returnInt(success);
							//somehow create check system to check if block is still valid (like scriptIdentifier) also get RID OF gVars inside shzblock() !!!
							blk_ref->resume();
#ifndef ARDUINO
							shz_global::get().syscall_wakeup();
#endif
						}))
					{
						blk->suspend();
					}
				}

				result.returnInt(send_id != INVALID_TICKETID);

			}, 5, true, false, "(cmd, data, sequential, timeout, wait_finish)");

		scriptFunction("get", [](ShizoNetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
		{
			result.initInt(0);

			if (!obj->m_device) { return; }

			if (params.size() < 1)
				return;
			if (params[0]->Type != SHZVAR_STRING)
				return;

			auto dtype = params.size() >= 2 ? params[1]->Type : SHZVAR_VOID;

			const char* cmd = params[0]->VarPtr.strptr->c_str();

			shznet_ticketid send_id = INVALID_TICKETID;

			auto param_data = &result;

			shzptr blk_ref(blk);

			auto respond_cb = [blk_ref, param_data](byte* data, size_t size, shznet_pkt_dataformat fmt, bool success)
				{
					if (!blk_ref.get())
						return;

					SCRIPTAUTOLOCK();

					if (!blk_ref.get())
						return;

					param_data->initInt(0);
					if (success)
					{
						data_to_var(fmt, data, size, param_data);
					}

					blk_ref->resume();
				};

			uint64_t timeout = params.size() >= 3 ? params[2]->get_int() : 0;

			switch (dtype)
			{
			case SHZVAR_INT:
			{
				int64_t v = params[1]->get_int();
				send_id = (obj->m_device->send_get(cmd,
					(byte*)&v,
					sizeof(int64_t),
					SHZNET_PKT_FMT_INT64, respond_cb, timeout));
				break;
			}
			case SHZVAR_FLOAT:
			{
				double v = params[1]->get_float();
				send_id = (obj->m_device->send_get(cmd,
					(byte*)&v,
					sizeof(double),
					SHZNET_PKT_FMT_FLOAT64, respond_cb, timeout));
				break;
			}
			case SHZVAR_STRING:
				send_id = (obj->m_device->send_get(cmd,
					(byte*)params[1]->VarPtr.strptr->c_str(),
					params[1]->VarPtr.strptr->length() + 1,
					SHZNET_PKT_FMT_STRING, respond_cb, timeout));
				break;
				/*case SHZVAR_shzobject:
				{
					SOH_Instance()->
					auto obj = SOH_Instance()->get_object(params[1]);
					if(obj)
						obj->
					break;
				}*/
			case SHZVAR_JSON:
			{
				if (obj->m_device->_has_shizoscript_json)
				{
					auto jh = params[1]->get_json();
					static uchar_array_s _tmp;
					_tmp.clear();
					jh->to_data(_tmp);

					send_id = (obj->m_device->send_get(cmd,
						(byte*)_tmp.data(),
						_tmp.size(),
						SHZNET_PKT_FMT_JSON, respond_cb, timeout));
					break;
				}
				else
				{
					auto jh = params[1]->get_json();
					auto kvw = shznet_kv_writer();
					for (auto it : jh->jsons)
					{
						if (!it->key.allocated() || it->key.get().empty())
						{
							SLH_Instance()->logerror("Cannot send empty keys (lists)!");
							continue;
						}

						if (it->is_int())
							kvw.add_int64(it->key.get().c_str(), it->get_int());
						else if (it->is_float())
							kvw.add_float64(it->key.get().c_str(), it->get_float());
						else if (it->is_string())
							kvw.add_string(it->key.get().c_str(), it->get_string_cptr());
						else if (it->is_data())
							kvw.add_data(it->key.get().c_str(), it->get_uchar_array()->data(), it->get_uchar_array()->size());
						//TODO: add json case, recursively shznet_kv_writer (sub objects not supported yet otherwise)
					}
					send_id = (obj->m_device->send_get(cmd,
						(byte*)kvw.get_buffer().data(),
						kvw.get_buffer().size(),
						SHZNET_PKT_FMT_KEY_VALUE, respond_cb, timeout));
					break;
				}
			}
			case SHZVAR_CHAR_ARRAY:
			case SHZVAR_UCHAR_ARRAY:
				send_id = (obj->m_device->send_get(cmd,
					(byte*)params[1]->get_uchar_array()->data(),
					params[1]->get_uchar_array()->size(),
					SHZNET_PKT_FMT_DATA, respond_cb, timeout));
				break;
			case SHZVAR_FLOAT_ARRAY:
				send_id = (obj->m_device->send_get(cmd,
					(byte*)params[1]->getFloatset()->data(),
					params[1]->getFloatset()->size() * sizeof(float),
					SHZNET_PKT_FMT_FLOAT32_ARRAY, respond_cb, timeout));
				break;
			case SHZVAR_DOUBLE_ARRAY:
				send_id = (obj->m_device->send_get(cmd,
					(byte*)params[1]->getDoubleset()->data(),
					params[1]->getFloatset()->size() * sizeof(double),
					SHZNET_PKT_FMT_FLOAT64_ARRAY, respond_cb, timeout));
				break;
			case SHZVAR_INT_ARRAY:
				send_id = (obj->m_device->send_get(cmd,
					(byte*)params[1]->getIntset()->data(),
					params[1]->getIntset()->size() * sizeof(int),
					SHZNET_PKT_FMT_INT32_ARRAY, respond_cb, timeout));
				break;
			case SHZVAR_LONG_ARRAY:
				send_id = (obj->m_device->send_get(cmd,
					(byte*)params[1]->getBigintset()->data(),
					params[1]->getBigintset()->size() * sizeof(long long),
					SHZNET_PKT_FMT_INT64_ARRAY, respond_cb, timeout));
				break;
			case SHZVAR_VOID:
				send_id = (obj->m_device->send_get(cmd,
					0,
					0,
					SHZNET_PKT_FMT_DATA, respond_cb, timeout));
				break;
			default:
				SLH_Instance()->logerror("invalid data type in get!");
				break;
			}

			if (send_id != INVALID_TICKETID)
				blk->suspend();
			else
				blk->runtimeError("NET", "Cannot get ticket id.");

			result.returnInt(send_id != INVALID_TICKETID);

		}, 3, true, false, "(cmd, data, timeout)");

	}

	void set_device(shznet_device_ptr dev)
	{
		m_device = dev;
		if (m_device)
			current_uid = m_device->get_unique_id();
		else
			current_uid = 0;
	}

};
SHZOBJECT_INSTANCE(ShizoNetDevice, "shizonet_device");

class ShizoArtnetDevice : public shzobject_ext<ShizoArtnetDevice>
{
	SHZOBJECT_DECLARE(ShizoArtnetDevice);

	shznet_artnet_device_ptr m_device;

	uint64_t current_uid = 0;

public:
	ShizoArtnetDevice(shznet_artnet_device_ptr dev = 0)
	{
		m_device = dev;
	}
	virtual ~ShizoArtnetDevice()
	{

	}
	virtual void free() override
	{
		//printf("shznet device free\n");
		delete this;
	}

	static void scriptRegister()
	{
		//legacy functions, remove someday
		scriptFunction("is_shizonet", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.initInt(0);
			}, 0, true, false, "()");
		scriptFunction("is_artnet", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.initInt(1);
			}, 0, true, false, "()");

		scriptFunction("get_name", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initString("");  return; }
				result.initString(obj->m_device->get_name().c_str());
			}, 0, true, false, "()");
		scriptFunction("get_mac", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initString("");  return; }
				result.initString(obj->m_device->get_mac().str().c_str());
			}, 0, true, false, "()");
		scriptFunction("get_ip", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initString("");  return; }
				result.initString(obj->m_device->get_ip().str().c_str());
			}, 0, true, false, "()");
		scriptFunction("still_valid", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initInt(0);  return; }
				result.initInt(1);
			}, 0, true, false, "() check if device is still online or if it is offline or has reconnected by the time (new session or invalid session)");
		scriptFunction("online", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (!obj->m_device) { result.initInt(0);  return; }
				result.initInt(1);
			}, 0, true, false, "() check if device is still online or if it is offline or has reconnected by the time (new session or invalid session)");


		scriptFunction("set_artnet_buffer", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() < 3)
					return;

				if (!obj->m_device) { return; }

				int universe = params[0]->get_int();
				int start_adr = params[1]->get_int();
				auto data_buffer = params[2]->is_int() ? 0 : params[2]->get_uchar_array();

				if (data_buffer)
				{
					size_t data_offset = params.size() >= 4 ? params[3]->get_int() : 0;
					size_t data_size = params.size() >= 5 ? std::min((size_t)params[4]->get_int(), data_buffer->size() - data_offset) : data_buffer->size() - data_offset;

					bool wrap_leds = params.size() >= 6 ? params[5]->get_int() : 0;

					obj->m_device->set_artnet_buffer(universe, start_adr, data_buffer->data(), data_size, data_offset, wrap_leds, params.size() >= 7 ? params[6]->get_int() : 1, params.size() >= 8 ? params[7]->get_int() : 0);
				}
				else
				{
					size_t data_offset = params.size() >= 4 ? params[3]->get_int() : 0;
					size_t data_size = params.size() >= 5 ? params[4]->get_int() : 0;

					bool wrap_leds = params.size() >= 6 ? params[5]->get_int() : 0;

					obj->m_device->set_artnet_buffer(universe, start_adr, (byte)params[2]->get_int(), data_size, data_offset, wrap_leds);
				}

			}, 8, true, false, "(universe, start_index, buffer, buffer_offset, buffer_size, wrap_leds, input_channels, target_channels)");

		scriptFunction("set_artnet_channel", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 3)
					return;

				if (!obj->m_device) { return; }

				int universe = params[0]->get_int();
				int start_adr = params[1]->get_int();
				byte value = params[2]->get_int();


				obj->m_device->set_artnet_buffer(universe, start_adr, &value, 1, 0, 0, 1, 1);

			}, 3, true, false, "(universe, index, value)");

		scriptFunction("clear_artnet_buffer", [](ShizoArtnetDevice* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (obj->m_device)
					obj->m_device->clear_artnet_buffer(params.size() == 1 ? params[0]->get_int() : 1);
			}, 1, true, false, "(set_dirty)");

	}

	void set_device(shznet_artnet_device_ptr dev)
	{
		m_device = dev;
	}
};
SHZOBJECT_INSTANCE(ShizoArtnetDevice, "artnet_device");

#include <cstdarg> // for va_list, va_start, va_end

class ShizoNetBase : public shzobject_ext<ShizoNetBase>, public shznet_server
{
	SHZOBJECT_DECLARE(ShizoNetBase);

	shzvar_shared m_artnet_dmx;
	shzvar_shared m_artnet_frame;

	virtual void on_device_connect(shznet_device_ptr dev_info) override 
	{
		shznet_server::on_device_connect(dev_info);

		if (m_connect_cbs.size())
		{
			SCRIPTAUTOLOCK();
			for (auto it = m_connect_cbs.begin(); it != m_connect_cbs.end();)
			{
				auto func = (*it)->getFunction();
				if (!func)
				{
					it = m_connect_cbs.erase(it); // Erase the element and update the iterator
					continue;
				}

				auto p1 = func->getParam(0);
				if (p1)
				{
					ShizoNetDevice* tmp_dev = new ShizoNetDevice(dev_info);
					tmp_dev->associateVar(p1);
				}
				func->run();
				++it; // Move to the next element
			}
		}
	};
	virtual void on_device_connect(shznet_artnet_device_ptr dev_info) override
	{
		shznet_server::on_device_connect(dev_info);

		if (m_artnet_connect_cbs.size())
		{
			SCRIPTAUTOLOCK();
			for (auto it = m_artnet_connect_cbs.begin(); it != m_artnet_connect_cbs.end();)
			{
				auto func = (*it)->getFunction();
				if (!func)
				{
					it = m_artnet_connect_cbs.erase(it); // Erase the element and update the iterator
					continue;
				}

				auto p1 = func->getParam(0);
				if (p1)
				{
					ShizoArtnetDevice* tmp_dev = new ShizoArtnetDevice(dev_info);
					tmp_dev->associateVar(p1);
				}
				func->run();
				++it; // Move to the next element
			}
		}
	};

	virtual void on_device_disconnect(shznet_device_ptr dev_info) 
	{
		shznet_server::on_device_disconnect(dev_info);
	};

	shzvector<shzvar_shared> m_connect_cbs;
	shzvector<shzvar_shared> m_artnet_connect_cbs;

	shzvar_shared m_on_remote_log;

	bool m_debugging = false;

public:

	static ShizoNetBase* global_base;

	ShizoNetBase(shzstring name = "DEFAULT", short port = ART_NET_PORT)
	{
		_has_shizoscript_json = true;

		if (!init(name.c_str(), port))
			SLH_Instance()->logerror("shznet: cannot bind to port %i!", port);
		global_base = this;
		/*m_base.setArtDmxCallback([this]())
		{

		}*/
		add_command("remote_log", [this](shznet_ip& adr, byte* data, size_t size, shznet_pkt_header& hdr)
			{
				auto dev = ShizoNetBase::global_base->find_device(hdr.macid_source);
				if (!dev || !data)
					return;
				SLH_Instance()->log("[%s]: %s", dev->get_name().c_str(), (char*)data);
				if (m_on_remote_log->Type == SHZVAR_FUNC)
				{
					SCRIPTAUTOLOCK();

					auto fn = m_on_remote_log->getFunction();

					if (!fn)
					{
						SLH_Instance()->logwarn("TODO: implement remove callback here!");
						return;
					}

					auto param_data = fn->getParam(0);
					auto param_dev = fn->getParam(1);

					if (param_data)
					{
						data_to_var(hdr.data_format, data, size, param_data);
					}

					if (param_dev)
					{
						ShizoNetDevice* tmp_dev = new ShizoNetDevice(dev);
						tmp_dev->associateVar(param_dev);
					}

					fn->run();
				}
			});
	}
	virtual ~ShizoNetBase()
	{
		global_base = 0;
	}

	virtual void free() override
	{
		delete this;
	}

	void scriptUpdate() override
	{
		update();
	}
	void scriptUpdateFlush() override
	{
		update();
		m_udp.flush_send_buffer();
	}

	std::vector<char> debug_log_buffer;
	inline void debug_log(const char* fmt, ...)
	{
		if (!m_debugging) return;

		// Start processing the variable arguments
		va_list args;
		va_start(args, fmt);

		// Determine the size needed for the formatted string
		va_list args_copy;
		va_copy(args_copy, args);
		int size = vsnprintf(nullptr, 0, fmt, args_copy) + 1; // +1 for null-terminator
		va_end(args_copy);

		// Create a string with the required size
		debug_log_buffer.resize(size);

		// Format the string with the arguments
		vsnprintf(debug_log_buffer.data(), size, fmt, args);

		// End the processing of variable arguments
		va_end(args);

		// Log the formatted message
		SLH_Instance()->log(debug_log_buffer.data());
	}
	bool is_debug() { return m_debugging; }

	static void scriptRegister()
	{
		scriptFunction("enable_shizonet", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1)
					return;

				obj->m_shizonet_enabled = params[0]->get_int();

			}, 1, true, false, "(enable)");

		scriptFunction("set_debug", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1)
					return;

				obj->m_debugging = params[0]->get_int();

			}, 1, true, false, "(enable)");

		scriptFunction("send_artnet_sync", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1)
					return;

				obj->send_artnet_sync = params[0]->get_int();

			}, 1, true, false, "(enable)");

		scriptFunction("on_connect", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1 || params[0]->Type != SHZVAR_FUNC)
					return;

				auto fn = params[0]->getFunction();

				if (!fn)
				{
					blk->runtimeError("shz_net", "Not a function!");
					return;
				}

				obj->m_connect_cbs.push_back(shzvar_shared(params[0]));

				for (auto it : obj->m_devices)
				{
					auto fn = params[0]->getFunction();

					if (!fn)
						return;

					auto p1 = fn->getParam(0);
					if (p1)
					{
						ShizoNetDevice* tmp_dev = new ShizoNetDevice(it.second);
						tmp_dev->associateVar(p1);
						fn->run();
					}
				}

			}, 1, true, false, "(cb)");

		scriptFunction("on_artnet_connect", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1 || params[0]->Type != SHZVAR_FUNC)
					return;

				auto fn = params[0]->getFunction();

				if (!fn)
				{
					blk->runtimeError("shz_net", "Not a function!");
					return;
				}

				obj->m_artnet_connect_cbs.push_back(shzvar_shared(params[0]));

				for (auto it : obj->m_artnet_devices)
				{
					auto fn = params[0]->getFunction();

					if (!fn)
						return;

					auto p1 = fn->getParam(0);
					if (p1)
					{
						ShizoArtnetDevice* tmp_dev = new ShizoArtnetDevice(it.second);
						tmp_dev->associateVar(p1);
						fn->run();
					}
				}

			}, 1, true, false, "(cb)");

		scriptFunction("on_command", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 2 || params[1]->Type != SHZVAR_FUNC)
					return;

				auto cmd = params[0]->get_string();

				auto fn = params[1]->blk;

				if (!fn)
					return;

				shzvar_shared runfn(params[1]);

				obj->add_command(cmd.c_str(), [runfn, obj](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
					{
						SCRIPTAUTOLOCK();

						auto dev = obj->find_device(hdr.macid_source);

						if (!dev)
							return;

						auto fn = runfn->getFunction();

						if (!fn)
						{
							SLH_Instance()->logwarn("TODO: implement remove callback here!");
							return;
						}

						auto param_data = fn->getParam(0);
						auto param_dev = fn->getParam(1);

						data_to_var(hdr.data_format, data, size, param_data);

						if (param_dev)
						{
							ShizoNetDevice* tmp_dev = new ShizoNetDevice(dev);
							tmp_dev->associateVar(param_dev);
						}

						fn->run();

					});

				shzptr ident(obj);

				blk->addCleanup([ident, cmd](void*) {if (ident.get()) ident.get()->remove_command(cmd.c_str()); }, 0, blk, 1, 0);

			}, 2, true, false, "(cmd, cb)");
		
		scriptFunction("on_stream", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 2 || params[1]->Type != SHZVAR_FUNC)
					return;

				auto cmd = params[0]->get_string();

				auto fn = params[1]->blk;

				if (!fn)
					return;

				shzvar_shared runfn(params[1]);

				obj->add_command(cmd.c_str(), [runfn, obj](shznet_ip& ip, byte* data, size_t size, shznet_pkt_header& hdr)
					{
						SCRIPTAUTOLOCK();

						auto dev = obj->find_device(hdr.macid_source);

						if (!dev)
							return;

						auto fn = runfn->getFunction();

						if (!fn)
						{
							SLH_Instance()->logwarn("TODO: implement remove callback here!");
							return;
						}

						auto param_data = fn->getParam(0);
						auto param_dev = fn->getParam(1);

						if (param_data)
						{
							data_to_var(hdr.data_format, data, size, param_data);
						}

						if (param_dev)
						{
							ShizoNetDevice* tmp_dev = new ShizoNetDevice(dev);
							tmp_dev->associateVar(param_dev);
						}

						fn->run();

					});

				obj->enable_stream(cmd.c_str());

				shzptr ident(obj);

				blk->addCleanup([ident, cmd](void*) {if (ident.get()) ident.get()->remove_command(cmd.c_str()); ident.get()->disable_stream(cmd.c_str()); }, 0, blk, 1, 0);

			}, 2, true, false, "(cmd, cb)");

		scriptFunction("on_get", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 2 || params[1]->Type != SHZVAR_FUNC)
					return;

				auto cmd = params[0]->get_string();

				auto fn = params[1]->blk;

				if (!fn)
					return;

				shzvar_shared runfn(params[1]);

				obj->add_command_respond(cmd.c_str(), [runfn, obj](std::shared_ptr<shznet_responder> responder)
					{
						SCRIPTAUTOLOCK();

						if (!responder->device())
							return;

						auto fn = runfn->getFunction();

						if (!fn)
						{
							SLH_Instance()->logwarn("TODO: implement remove callback here!");
							return;
						}
						auto param_data = fn->getParam(0);
						auto param_dev = fn->getParam(1);

						auto data = responder->data();
						auto size = responder->size();

						if (param_data)
						{
							data_to_var(responder->format(), data, size, param_data);
						}

						if (param_dev)
						{
							ShizoNetDevice* tmp_dev = new ShizoNetDevice(responder->device_ptr());
							tmp_dev->associateVar(param_dev);
						}

						auto fn_res = fn->run();

						auto respond_fn = [](std::shared_ptr<shznet_responder> resp, shzvar* var)
							{
								var_to_responder(var, resp);
							};

						if (!fn->running())
						{
							respond_fn(responder, fn_res);
						}
						else
						{
							fn->thread_data->thread_result = [responder, respond_fn](shzblock* blk, shzvar* result)
								{
									respond_fn(responder, result);
								};
						}
					});

				shzptr ident(obj);

				blk->addCleanup([ident, cmd](void*) {if (ident.get()) ident.get()->remove_command(cmd.c_str()); }, 0, blk, 1, 0);

			}, 2, true, false, "(cmd, cb)");
		
		scriptFunction("on_remote_log", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
		{
			if (params.size() != 1 || params[0]->Type != SHZVAR_FUNC)
				return;

			obj->m_on_remote_log->set(params[0]);

		}, 1, true, false, "(cb)");


		scriptFunction("set_name", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1)
					return;

				obj->set_node_name(params[0]->get_string().c_str());

			}, 1, true, false, "(name)");

		scriptFunction("get_mac", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.initString(obj->local_mac().str().c_str());

			}, 0, true, false, "()");

		scriptFunction("get_ip", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.initString(obj->local_ip().str().c_str());

			}, 0, true, false, "()");

		//IMPLEMENT SCRIPT FUNCTION THAT EXTERNAL FUNCTIONS CAN RETURN ARRAYS !!!
		scriptFunction("for_each_device", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1 || params[0]->Type != SHZVAR_FUNC)
					return;

				ShizoNetDevice tmp_dev(0);

				for (auto it : obj->m_devices)
				{
					auto fn = params[0]->getFunction();
					if (!fn)
						return;

					tmp_dev.set_device(it.second);
					tmp_dev.associateVar(fn->getParam(0));
					fn->run();
				}
			}, 1, true, false, "()");

		scriptFunction("for_each_artnet_device", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1 || params[0]->Type != SHZVAR_FUNC)
					return;

				ShizoArtnetDevice tmp_dev(0);

				for (auto it : obj->m_artnet_devices)
				{
					auto fn = params[0]->getFunction();
					if (!fn)
						return;

					tmp_dev.set_device(it.second);
					tmp_dev.associateVar(fn->getParam(0));
					fn->run();
				}

			}, 1, true, false, "()");

		scriptFunction("clear_artnet_buffers", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				for (auto it : obj->m_artnet_devices)
				{
					it.second->clear_artnet_buffer(params.size() == 1 ? params[0]->get_int() : 1);
				}

			}, 1, true, false, "(set_dirty)");

		scriptFunction("get_devices", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.get_json()->clear();

				for (auto it : obj->m_devices)
				{
					auto nv = result.get_json()->push_var();

					auto dev_object = new ShizoNetDevice(it.second);

					dev_object->associateVar(nv, blk);
				}

			}, 0, true, false, "()");
		scriptFunction("get_artnet_devices", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.get_json()->clear();

				for (auto it : obj->m_artnet_devices)
				{
					auto nv = result.get_json()->push_var();

					auto dev_object = new ShizoArtnetDevice(it.second);

					dev_object->associateVar(nv, blk);
				}
			}, 0, true, false, "()");

		scriptFunction("get_offline_devices", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.get_json()->clear();

				for (auto it : obj->m_devices_offline)
				{
					auto nv = result.get_json()->push_var();

					auto dev_object = new ShizoNetDevice(it.second);

					dev_object->associateVar(nv, blk);
				}
				/*for (auto it : obj->m_artnet_devices_offline)
				{
					auto nv = result.get_json()->push_var();

					auto dev_object = new ShizoNetDevice(it.second);

					dev_object->associateVar(nv, blk);
				}*/
			}, 0, true, false, "()");
		scriptFunction("get_device_mac", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1)
					return;
				auto mac = params[0]->get_string();
				for (auto it : obj->m_devices)
				{
					auto dev_mac = it.second->get_mac().str();
					if (dev_mac.compare(mac) == 0)
					{
						auto dev_object = new ShizoNetDevice(it.second);
						dev_object->associateVar(&result, blk);
						return;
					}
				}

				result.initInt(0);
			}, 1, true, false, "(mac)");
	
		scriptFunction("get_artnet_device_mac", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				if (params.size() != 1)
					return;
				auto mac = params[0]->get_string();

				for (auto it : obj->m_artnet_devices)
				{
					auto dev_mac = it.second->get_mac().str();
					if (dev_mac.compare(mac) == 0)
					{
						auto dev_object = new ShizoArtnetDevice(it.second);
						dev_object->associateVar(&result, blk);
						return;
					}
				}

				result.initInt(0);
			}, 1, true, false, "(mac)");

		scriptFunction("get", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				result.initInt(0);

				if (params.size() < 1)
				{
					result.returnError("invalid params.");
					return;
				}
				if (params[0]->Type != SHZVAR_STRING)
				{
					result.returnError("invalid params.");
					return;
				}
				auto dtype = params.size() >= 2 ? params[1]->Type : SHZVAR_VOID;

				const char* cmd = params[0]->VarPtr.strptr->c_str();

				uint64_t timeout = params.size() >= 3 ? params[2]->get_int() : 0;

				uint32_t cmd_hash = shznet_hash((char*)cmd, params[0]->VarPtr.strptr->length());

				shznet_device_ptr dev = 0;

				for (auto& it : obj->m_devices)
				{
					if (it.second->command_response_map.find(cmd_hash) != it.second->command_response_map.end())
					{
						dev = it.second;
						break;
					}

				}

				shznet_ticketid send_id = INVALID_TICKETID;

				auto param_data = &result;

				shzptr blk_ref(blk);

				auto respond_cb = [blk_ref, param_data](byte* data, size_t size, shznet_pkt_dataformat fmt, bool success)
					{
						if (!blk_ref.get())
							return;

						SCRIPTAUTOLOCK();
						
						if (!blk_ref.get())
							return;
						
						param_data->initInt(0);
						if (success)
						{
							data_to_var(fmt, data, size, param_data);
						}
						else
							param_data->returnError("command failed.");
						blk_ref->resume();
					};

				if (!dev) //todo, offload onto update() and timeout after 30 seconds (dont return error directly wait for devices)
				{
					SLH_Instance()->logerror("no device found for cmd: %s\n", cmd);

					SLH_Instance()->log("Devices:");

					for (auto& it : obj->m_devices)
					{
						SLH_Instance()->log(" - %s (%i)", it.second->get_name().c_str(), (int)it.second->command_response_map.size());
					}

					result.returnError("no device.");

					//temp fix, force sleep to for 1 sec to avoid spam

					return;
				}

				if (obj->is_debug())
				{
					uint64_t longest_time = 0;
					for (auto& it : dev->get_unordered_buffers())
					{
						auto d = it->start_time.delay();
						if (d > longest_time)
							longest_time = d;
					}

					obj->debug_log("The device has (%llu | %llu | %u) open orders (oldest is %llus). (err = %f, max = %f)", dev->get_ordered_buffers().size(), dev->get_unordered_buffers().size(), dev->num_zombie_buffers(), longest_time / 1000, dev->get_error_rate(), dev->get_packets_per_ms());
				}

				switch (dtype)
				{
				case SHZVAR_INT:
				{
					int64_t v = params[1]->get_int();
					send_id = (dev->send_get(cmd,
						(byte*)&v,
						sizeof(int64_t),
						SHZNET_PKT_FMT_INT64, respond_cb, timeout));
					break;
				}
				case SHZVAR_FLOAT:
				{
					double v = params[1]->get_float();
					send_id = (dev->send_get(cmd,
						(byte*)&v,
						sizeof(double),
						SHZNET_PKT_FMT_FLOAT64, respond_cb, timeout));
					break;
				}
				case SHZVAR_STRING:
					send_id = (dev->send_get(cmd,
						(byte*)params[1]->VarPtr.strptr->c_str(),
						params[1]->VarPtr.strptr->length() + 1,
						SHZNET_PKT_FMT_STRING, respond_cb, timeout));
					break;
					/*case SHZVAR_shzobject:
					{
						SOH_Instance()->
						auto obj = SOH_Instance()->get_object(params[1]);
						if(obj)
							obj->
						break;
					}*/
				case SHZVAR_JSON:
				{
					if (dev->_has_shizoscript_json)
					{
						auto jh = params[1]->get_json();
						static uchar_array_s _tmp;
						_tmp.clear();
						jh->to_data(_tmp);

						send_id = (dev->send_get(cmd,
							(byte*)_tmp.data(),
							_tmp.size(),
							SHZNET_PKT_FMT_JSON, respond_cb, timeout));
						break;
					}
					else
					{
						auto jh = params[1]->get_json();
						auto kvw = shznet_kv_writer();
						for (auto it : jh->jsons)
						{
							if (!it->key.allocated() || it->key.get().empty())
							{
								SLH_Instance()->logerror("Cannot send empty keys (lists)!");
								continue;
							}

							if (it->is_int())
								kvw.add_int64(it->key.get().c_str(), it->get_int());
							else if (it->is_float())
								kvw.add_float64(it->key.get().c_str(), it->get_float());
							else if (it->is_string())
								kvw.add_string(it->key.get().c_str(), it->get_string_cptr());
							else if (it->is_data())
								kvw.add_data(it->key.get().c_str(), it->get_uchar_array()->data(), it->get_uchar_array()->size());
							//TODO: add json case, recursively shznet_kv_writer (sub objects not supported yet otherwise)
						}

						send_id = (dev->send_get(cmd,
							(byte*)kvw.get_buffer().data(),
							kvw.get_buffer().size(),
							SHZNET_PKT_FMT_KEY_VALUE, respond_cb, timeout));
						break;
					}
				}
				case SHZVAR_CHAR_ARRAY:
				case SHZVAR_UCHAR_ARRAY:
					send_id = (dev->send_get(cmd,
						(byte*)params[1]->get_uchar_array()->data(),
						params[1]->get_uchar_array()->size(),
						SHZNET_PKT_FMT_DATA, respond_cb, timeout));
					break;
				case SHZVAR_FLOAT_ARRAY:
					send_id = (dev->send_get(cmd,
						(byte*)params[1]->getFloatset()->data(),
						params[1]->getFloatset()->size() * sizeof(float),
						SHZNET_PKT_FMT_FLOAT32_ARRAY, respond_cb, timeout));
					break;
				case SHZVAR_DOUBLE_ARRAY:
					send_id = (dev->send_get(cmd,
						(byte*)params[1]->getDoubleset()->data(),
						params[1]->getFloatset()->size() * sizeof(double),
						SHZNET_PKT_FMT_FLOAT64_ARRAY, respond_cb, timeout));
					break;
				case SHZVAR_INT_ARRAY:
					send_id = (dev->send_get(cmd,
						(byte*)params[1]->getIntset()->data(),
						params[1]->getIntset()->size() * sizeof(int),
						SHZNET_PKT_FMT_INT32_ARRAY, respond_cb, timeout));
					break;
				case SHZVAR_LONG_ARRAY:
					send_id = (dev->send_get(cmd,
						(byte*)params[1]->getBigintset()->data(),
						params[1]->getBigintset()->size() * sizeof(long long),
						SHZNET_PKT_FMT_INT64_ARRAY, respond_cb, timeout));
					break;
				case SHZVAR_VOID:
					send_id = (dev->send_get(cmd,
						0,
						0,
						SHZNET_PKT_FMT_DATA, respond_cb, timeout));
				default:
					SLH_Instance()->logerror("invalid data type in send_fast!");
					break;
				}

				if (send_id != INVALID_TICKETID)
					blk->suspend();

				if (send_id == INVALID_TICKETID)
					result.returnError("invalid ticket.");

			}, 3, true, false, "(cmd, data, timeout_ms)");

		scriptFunction("artnet_sync", [](ShizoNetBase* obj, shzblock* blk, shzvector<shzvar*>& params, shzvar& result)
			{
				obj->artnet_sync_now();

			}, 0, true, false, "()");
}
};

SHZOBJECT_INSTANCE(ShizoNetBase, "shizonet_base");

ShizoNetBase* ShizoNetBase::global_base;


shz_module_loader loader_netbase([](shzscript* s)
	{
#ifdef ARDUINO
		ShizoNetBase::global_base = new ShizoNetBase();
		ShizoNetBase::global_base->scriptIncreaseRef();
		s->register_update(shzptr<shzobject>(ShizoNetBase::global_base));
		s->register_update_flush(shzptr<shzobject>(ShizoNetBase::global_base));

		ShizoNetBase::global_base->add_command_respond("run_prompt", [s](std::shared_ptr<shznet_responder> r)
			{
				if (r->format() == SHZNET_PKT_FMT_STRING)
					s->run_prompt((char*)r->data());
				else
					r->respond_fail("invalid pkt format, needs to be of type 'string'");
			});

#ifdef __XTENSA__
		ShizoNetBase::global_base->add_command_respond("reboot", [s](std::shared_ptr<shznet_responder> r)
			{
				ESP.restart();
			});
#endif
		ShizoNetBase::global_base->add_command_respond("debug_log", [s](std::shared_ptr<shznet_responder> r)
			{
				auto dev = r->device_ptr();
				if (!dev)
					return;

				auto sid = dev->get_sessionid();

				SLH_Instance()->addLogCB([dev, sid](ScriptLogType type, char* str)
					{
						SCRIPTAUTOLOCK();
						if (!dev->valid() || !dev->online() || dev->get_sessionid() != sid)
							return false;

						static int log_feedback_fix;

						if (log_feedback_fix)
							return true;

						log_feedback_fix = 1;

						dev->send_reliable("remote_log", (byte*)str, strlen(str) + 1, SHZNET_PKT_FMT_STRING);

						log_feedback_fix = 0;

						return true;
					});
			});
#endif

		s->addExtClass<ShizoNetBase>("shizonet_base", [s](shzblock* blk, shzvector<shzvar*>& params, void* usrdata, shzvar& result)
			{
				ShizoNetBase* tmp = ShizoNetBase::global_base;
				if (!tmp)
				{
					tmp = new ShizoNetBase(params.size() >= 1 ? params[0]->get_string() : "DEFAULT", params.size() >= 2 ? params[1]->get_int() : ART_NET_PORT);
					s->register_update(shzptr<shzobject>(tmp));
					s->register_update_flush(shzptr<shzobject>(tmp));
				}

				tmp->associateVar(&result);
				tmp->set_node_name(params.size() >= 1 ? params[0]->get_string().c_str() : "DEFAULT");
				return &result;
			}, 2, 0, "(node_name, udp_port=artnet_port)", true);

	});

#ifdef ARDUINO
void shz_netbase_remote(shzscript* s, std::function<bool(const char*)> run_script_cb)
{
	ShizoNetBase::global_base->add_command_respond("run_script", [s, run_script_cb](std::shared_ptr<shznet_responder> r)
		{
			if (r->format() == SHZNET_PKT_FMT_STRING)
				run_script_cb((const char*)r->data());
			else
				r->respond_fail("invalid pkt format, needs to be of type 'string'");
		});
}
#endif

//NOT NEEDED IN NEWER ARDUINO VERSIONS, UNCOMMENT IF ERROR
/*
#ifdef __XTENSA__
#include "esp_random.h"
//FIX FOR ESP32 S3
int getentropy(void* buffer, size_t length)
{
	esp_fill_random(buffer, length);
	return 0;
}
#endif
*/