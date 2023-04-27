package app.attestation.auditor;

import java.io.IOException;

import com.google.common.collect.ImmutableMap;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import android.content.Context;
import android.content.res.XmlResourceParser;
import android.util.Log;

interface XmlMapElemParser<K, V> {
    public K parseKey(Context context, XmlResourceParser parser);

    public V parseValue(Context context, XmlResourceParser parser);
}

public class ImmutableMapParser {
    public static <K, V> ImmutableMap<K, V> getImmutableMapResource(Context context, int hashMapResId,
            String keyTagName, String valueTagName, XmlMapElemParser<K, V> mapElemParser)
            throws XmlPullParserException, IOException, IllegalArgumentException {
        ImmutableMap.Builder<K, V> map = null;
        XmlResourceParser parser = context.getResources().getXml(hashMapResId);

        K key = null;
        V value = null;

        int eventType = parser.getEventType();

        while (eventType != XmlPullParser.END_DOCUMENT) {
            if (eventType == XmlPullParser.START_DOCUMENT) {
                Log.d("ImmutableMapParser", "Start document");
            } else if (eventType == XmlPullParser.START_TAG) {
                if (parser.getName().equals("map")) {
                    Log.d("ImmutableMapParser", "parsing map");
                    map = ImmutableMap.<K, V>builder();
                } else if (parser.getName().equals("entry")) {
                    Log.d("ImmutableMapParser", "parsing entry");
                } else if (parser.getName().equals(keyTagName)) {
                    key = mapElemParser.parseKey(context, parser);
                } else if (parser.getName().equals(valueTagName)) {
                    value = mapElemParser.parseValue(context, parser);
                }
            } else if (eventType == XmlPullParser.END_TAG) {
                if (parser.getName().equals("entry")) {
                    map.put(key, value);
                    key = null;
                    value = null;
                }
            }
            eventType = parser.next();
        }

        return map.build();
    }
}
