package com.k2cybersecurity.intcodeagent.websocket;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.apache.commons.lang3.StringEscapeUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

public class JsonConverter {

	private static final String JSON_SEPRATER = "\":";
	private static final String STR_FORWARD_SLASH = "\"";
	private static final String STR_COMMA = ",";
	private static final String STR_END_CUELY_BRACKET = "}";
	private static final String STR_START_CUELY_BRACKET = "{";

	public static String toJSON(Object obj) {
		StringBuilder jsonString = new StringBuilder(STR_START_CUELY_BRACKET);

		Class<?> objClass = obj.getClass();
		Class<?> superClass = obj.getClass().getSuperclass();

		Field[] superFields = superClass.getDeclaredFields();
		if (superFields.length > 1) {
			jsonString.append(getFieldsAsJsonString(superFields, obj));
			jsonString.append(STR_COMMA);
		}
		Field[] objFields = objClass.getDeclaredFields();
		jsonString.append(getFieldsAsJsonString(objFields, obj));
		jsonString.append(STR_END_CUELY_BRACKET);
		return jsonString.toString();
	}
	
	public static String toJSON(Map<String, Object> obj) {
		StringBuilder jsonString = new StringBuilder();
		JSONObject mapObject = new JSONObject();
		mapObject.putAll(processMap(obj));
		jsonString.append(mapObject.toJSONString());
		return jsonString.toString();
	}

	private static String getFieldsAsJsonString(Field[] fields, Object obj) {
		StringBuilder jsonString = new StringBuilder();
		for (int i = 0; i < fields.length; i++) {
			try {
				if (!Modifier.isStatic(fields[i].getModifiers())) {
					Field field = fields[i];
					field.setAccessible(true);
					if (field.getAnnotation(JsonIgnore.class) != null) {
						continue;
					}
					Object value = field.get(obj);
					if (value != null) {
						jsonString.append(STR_FORWARD_SLASH);
						jsonString.append(field.getName());
						jsonString.append(JSON_SEPRATER);
						if (field.getType().equals(String.class)) {
							jsonString.append(STR_FORWARD_SLASH);
							jsonString.append(StringEscapeUtils.escapeJava(value.toString()));
							jsonString.append(STR_FORWARD_SLASH);
						} else if (field.getType().isPrimitive()) {
							jsonString.append(value);
						} else if (field.getType().isAssignableFrom(Set.class)) {
							JSONArray setField = new JSONArray();
							setField.addAll(processCollection((Set) value));
							jsonString.append(setField);
						} else if (field.getType().isArray()) {
							JSONArray setField = new JSONArray();
							setField.addAll(processCollection(Arrays.asList((Object[]) value)));
							jsonString.append(setField);
						} else if (field.getType().isAssignableFrom(List.class)) {
							JSONArray setField = new JSONArray();
							setField.addAll(processCollection((List) value));
							jsonString.append(setField);
						} else if (field.getType().isAssignableFrom(Map.class)) {
							JSONObject mapField = new JSONObject();
							mapField.putAll(processMap((Map) value));
							jsonString.append(mapField);
						} else {
							jsonString.append(value.toString());
						}
						jsonString.append(STR_COMMA);
					}
				}
			} catch (IllegalArgumentException | IllegalAccessException e) {

			}
		}

		jsonString.deleteCharAt(jsonString.length() - 1);
		return jsonString.toString();
	}

	private static Map processMap(Map<String, Object> value) {
		Map<String, Object> mapObject = new HashMap<>();
		for (Entry<String, Object> entry : value.entrySet()) {
			mapObject.put(entry.getKey(), processValue(entry.getValue()));
		}

		return mapObject;
	}

	private static Object processValue(Object value) {
		if (value instanceof Collection) {
			return processCollection((Collection<Object>) value);
		} else if (value instanceof Object[]) {
			return processCollection(Arrays.asList((Object[]) value));
		} else if (value instanceof Map) {
			return processMap((Map) value);
		} else {
			return value;
		}
	}

	private static Collection processCollection(Collection<Object> values) {
		List<Object> list = new ArrayList<>();
		for (Object value : values) {
			if (value instanceof Collection || value instanceof Object[]) {
				list.addAll((Collection<? extends Object>) processValue(value));
			} else {
				list.add(processValue(value));
			}
		}
		return list;
	}

//	public static void main(String[] args) {
//
//		String[] arr = new String[] {"as", "vd"};
//
//
//		JavaAgentEventBean javaAgentEventBean = new JavaAgentEventBean(System.currentTimeMillis(), 15L, "source", 12121,
//				"asdasd-1212-sdf", "12-12", VulnerabilityCaseType.DB_COMMAND);
//		JSONArray jsonArray = new JSONArray();
//		jsonArray.add("sadasda");
//		jsonArray.add("sadasdaasdfasd");
//		jsonArray.addAll(Arrays.asList(arr));
//		javaAgentEventBean.setParameters(jsonArray);
//
//		ServletInfo servletInfo = new ServletInfo();
//		servletInfo.setDataTruncated(false);
//		servletInfo.setRawRequest("sdasdfasfasf \n\r asd \r\n asd asd asd ");
//		javaAgentEventBean.setHttpRequestBean(servletInfo);
//
//		System.out.println(javaAgentEventBean.toString());
//	}
}
