import argparse
import concurrent.futures
import json
import os
import re

import folium
import requests
import yaml
from google.protobuf.message import DecodeError
from flask import Flask, jsonify, request

app = Flask(__name__)

# import the BSSIDResp protobuf message from the BSSIDApple_pb2 module
from helpers.BSSIDApple_pb2 import BSSIDResp

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def wigle_ssid(ssid_param):
    """Searches for a network with a specific SSID in the Wigle database.

    Parameters:
        ssid_param (str): The SSID of the network to search for.

    Returns:
        list: A list of dictionaries, each containing information about a network. If an error occurred, the list will contain a single dictionary with an error message.
    """
    # Get the Wigle API key from the configuration data
    api_key = os.getenv("wigle_auth")
    # Set the headers for the request
    headers = {
        'accept': 'application/json',
        'Authorization': f'Basic {api_key}'
    }
    # Set the parameters for the request
    params = {'ssid': ssid_param}
    # Set the endpoint for the request
    endpoint = 'https://api.wigle.net/api/v2/network/search'
    try:
        # Send the GET request
        response = requests.get(
            endpoint,
            headers=headers,
            params=params,
            # Disable SSL verification if specified in the configuration data
            verify=False
        )
        # If the request is successful
        if response.json()['success']:
            # If the request is successful
            if response.json()['totalResults'] != 0:
                # Get the results from the response
                results = response.json()['results']
                # Create a list of dictionaries containing the data
                data = [{
                    'module': 'wigle',
                    'bssid': result.get('netid', ''),
                    'ssid': result.get('ssid', ''),
                    'latitude': result.get('trilat', ''),
                    'longitude': result.get('trilong', '')
                } for result in results]
                return data
            else:
                return
        else:
            return
    except Exception as e:
        return

def wifidb_ssid(ssid_param):
    """Searches for a network with a specific SSID in the wifidb database.

    Parameters:
        ssid_param (str): The SSID of the network to search for.

    Returns:
        list: A list of dictionaries, each containing information about a network. If an error occurred, the list will contain a single dictionary with an error message.
    """
    # Set the parameters for the request
    params = {
        'func': 'exp_search',
        'ssid': ssid_param,
        'mac': '',
        'radio': '',
        'chan': '',
        'auth': '',
        'encry': '',
        'sectype': '',
        'json': 0,
        'labeled': 0
    }
    # Set the endpoint for the request
    endpoint = 'https://wifidb.net/wifidb/api/geojson.php'
    try:
        # Send the GET request
        response = requests.get(
            endpoint,
            params=params,
            # Disable SSL verification if specified in the configuration data
            verify=False
        )
        # If the request is successful
        if response.status_code == 200:
            # Get the results from the response
            results = response.json()['features']
            # Check if the SSID is in the results
            if len(results) > 0:
                # Create a list of dictionaries containing the data
                data = [{
                    'module': 'wifidb',
                    'bssid': result['properties']['mac'],
                    'ssid': result['properties']['ssid'],
                    'latitude': result['properties']['lat'],
                    'longitude': result['properties']['lon']
                } for result in results]
                return data
            else:
                return
        else:
            return
    except Exception as e:
        return

def openwifimap_ssid(ssid_param):
    """Searches for a node with a specific SSID in the openwifimap.net database.

    Parameters:
        ssid_param (str): The SSID of the node to search for.

    Returns:
        dict: A dictionary containing information about the node, or an error message if an error occurred.
    """
    # Set the endpoint for the request
    endpoint = 'https://api.openwifimap.net/view_nodes'
    # Set the headers for the request
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    # Set the request body
    data = {'keys': [ssid_param]}
    try:
        # Send the POST request
        response = requests.post(
            endpoint,
            headers=headers,
            json=data,
            # Disable SSL verification if specified in the configuration data
            verify=False
        )
        # If the request is successful
        if response.status_code == 200:
            # Get the results from the response
            results = response.json()['rows']
            # If there are no results, return an error message
            if not results:
                return
            # Extract the relevant fields from the first result
            result = results[0]['value']
            # Create the output dictionary using a dictionary comprehension
            data = {
                'module': 'openwifimap',
                'ssid': ssid_param,
                'hostname': result['hostname'],
                'latitude': result['latlng'][0],
                'longitude': result['latlng'][1]
            }
            return data
        else:
            return
    except Exception as e:
        return

def freifunk_karte_ssid(ssid_param):
    """Searches for a network with a specific SSID in the freifunk-karte.de database.

    Parameters:
        ssid_param (str): The SSID of the network to search for.

    Returns:
        dict: A dictionary containing information about the network, or an error message if an error occurred.
    """
    # Set the endpoint for the request
    endpoint = 'https://www.freifunk-karte.de/data.php'
    try:
        # Send the GET request
        response = requests.get(
            endpoint,
            # Disable SSL verification if specified in the configuration data
            verify=False
        )
        # If the request is successful
        if response.status_code == 200:
            # Get the results from the response
            results = response.json()['allTheRouters']
            # Check if the SSID is in the results
            for result in results:
                if result['name'] == ssid_param:
                    # Extract the relevant fields from the result
                    data = {
                        'module': 'freifunk-karte',
                        'ssid': result['name'],
                        'latitude': result['lat'],
                        'longitude': result['long'],
                        'community': result['community'],
                    }
                    return data
            return
        else:
            return
    except Exception as e:
        return

def wigle_bssid(bssid_param):
    """Searches for a network with a specific BSSID in the Wigle database.

    Parameters:
        bssid_param (str): The BSSID of the network to search for.

    Returns:
        list: A list of dictionaries, each containing information about a network. If an error occurred, the list will contain a single dictionary with an error message.
    """
    # Get the Wigle API key from the configuration data
    api_key = os.getenv("wigle_auth")
    # Set the headers for the request
    headers = {
        'accept': 'application/json',
        'Authorization': f'Basic {api_key}'
    }
    # Set the parameters for the request
    params = {'netid': bssid_param}
    # Set the endpoint for the request
    endpoint = 'https://api.wigle.net/api/v2/network/search'
    try:
        # Send the GET request
        response = requests.get(
            endpoint,
            headers=headers,
            params=params,
            # Disable SSL verification if specified in the configuration data
            verify=False
        )
        # If the request is successful
        if response.json()['success']:
            # If the request is successful
            if response.json()['totalResults'] != 0:
                # Get the results from the response
                results = response.json()['results']
                # Create a list of dictionaries containing the data
                data = [{
                    'module': 'wigle',
                    'bssid': result.get('netid', ''),
                    'ssid': result.get('ssid', ''),
                    'latitude': result.get('trilat', ''),
                    'longitude': result.get('trilong', '')
                } for result in results]
                return data
            else:
                return
        else:
            return
    except Exception as e:
        return

def mylnikov_bssid(bssid_param):
    """Searches for a network with a specific BSSID in the mylnikov database.

    Parameters:
        bssid_param (str): The BSSID of the network to search for.

    Returns:
        dict: A dictionary containing information about the network, or an error message if an error occurred.
    """

    # Set up the HTTP headers
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Set up the query parameters with the BSSID
    params = {'bssid': bssid_param}

    # Set the endpoint for the request
    endpoint = 'https://api.mylnikov.org/geolocation/wifi?v=1.1&data=open'
    # Make the HTTP POST request to the mylnikov API
    try:
        # Send the POST request
        response = requests.post(
            endpoint,
            headers=headers,
            params=params,
            # Disable SSL verification if specified in the configuration data
            verify=False
        )
        # Check if the request was successful
        if response.json()['result'] == 200:
            # Extract the relevant fields from the response
            result = response.json()['data']
            # Create the output dictionary using a dictionary comprehension
            data = {
                'module': 'mylnikov',
                'bssid': bssid_param,
                'latitude': result['lat'],
                'longitude': result['lon']
            }
            return data
        else:
            return
    except Exception as e:
        return

def apple_bssid(bssid_param):
    """Searches for a network with a specific BSSID in the Apple database.

    Parameters:
        bssid_param (str): The BSSID of the network to search for.

    Returns:
        dict: A dictionary containing information about the network, or an error message if an error occurred.
    """

    # Set up the HTTP headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
        'Accept-Charset': 'utf-8',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-us',
        'User-Agent': 'locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0'
    }

    # Set up the POST data
    data_bssid = f'\x12\x13\n\x11{bssid_param}\x18\x00\x20\01'
    data = '\x00\x01\x00\x05en_US\x00\x13com.apple.locationd\x00\x0a' + '8.1.12B411\x00\x00\x00\x01\x00\x00\x00' + chr(
        len(data_bssid)) + data_bssid
    # Set the endpoint for the request
    endpoint = 'https://gs-loc.apple.com/clls/wloc'
    # Make the HTTP POST request using the requests library
    response = requests.post(
        endpoint,
        headers=headers,
        data=data,
        verify=False
    )

    # Parse the binary content of the response into a BSSIDResp protobuf object.
    bssid_response = BSSIDResp()
    try:
        bssid_response.ParseFromString(response.content[10:])
    except DecodeError as e:
        return f'Failed to decode response: {e}'
    lat_match = re.search('lat: (\S*)', str(bssid_response))
    lon_match = re.search('lon: (\S*)', str(bssid_response))
    try:
        # Extract the latitude and longitude values from the response
        lat = lat_match.group(1)
        lon = lon_match.group(1)

        if '18000000000' not in lat:
            # format the latitude and longitude values
            lat = float(lat[:-8] + '.' + lat[-8:])
            lon = float(lon[:-8] + '.' + lon[-8:])
            # create the output dictionary
            data = {
                'module': 'apple',
                'bssid': bssid_param,
                'latitude': lat,
                'longitude': lon
            }
            return data
        else:
            return
    except Exception as e:
        if not lat_match or not lon_match:
            return
        return

def google_bssid(bssid_param):
    """Searches for a network with a specific BSSID in the Google geolocation API.

    Parameters:
        bssid_param (str): The BSSID of the network to search for.

    Returns:
        dict: A dictionary containing information about the network, or an error message if an error occurred.
    """

    # Get the Comba.in API key from the configuration data
    api_key = os.getenv("google_api")
    # Set up the HTTP headers
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json'
    }
    # Set up the query parameters with the BSSID
    params = {
        'considerIp': 'false',
        'wifiAccessPoints': [
            {
                'macAddress': bssid_param,
                'signalStrength': -30
            },
            {
                'macAddress': '14:84:73:0A:76:E9',
                'signalStrength': -90
            }
        ]
    }
    # Set the endpoint for the request
    endpoint = f'https://www.googleapis.com/geolocation/v1/geolocate?key={api_key}'
    # Make the HTTP POST request to the Google geolocation API
    try:
        response = requests.post(
            endpoint,
            headers=headers,
            json=params,
            verify=False
        )
        # Check if the request was successful
        if response.status_code == 200:
            # Extract the relevant fields from the response
            result = response.json()
            # Create the output dictionary using a dictionary comprehension
            data = {
                'module': 'google',
                'bssid': bssid_param,
                'latitude': result['location']['lat'],
                'longitude': result['location']['lng']
            }
            return data
        else:
            return
    except Exception as e:
        return

def combain_bssid(bssid_param):
    """Searches for a network with a specific BSSID in the Comba.in database.

    Parameters:
        bssid_param (str): The BSSID of the network to search for.

    Returns:
        dict: A dictionary containing information about the network, or an error message if an error occurred.
    """
    # Get the Comba.in API key from the configuration data
    api_key = os.getenv("combain_api")
    # Set the headers for the request
    headers = {
        'Content-Type': 'application/json',
    }
    # Set the parameters for the request
    params = {
        'wifiAccessPoints': [{
            'macAddress': bssid_param,
            'macAddress': '28:28:5d:d6:39:8a'
        }],
        'indoor': 1
    }
    # Set the endpoint for the request
    endpoint = f'https://apiv2.combain.com?key={api_key}'
    try:
        # Send the POST request
        response = requests.post(
            endpoint,
            headers=headers,
            json=params,
            # Disable SSL verification if specified in the configuration data
            verify=False
        )
        # If the request is successful
        if response.status_code == 200:
            # Extract the relevant fields from the response
            result = response.json()
            data = {
                'module': 'combain',
                'bssid': bssid_param,
                'latitude': result['location']['lat'],
                'longitude': result['location']['lng'],
            }
            if 'indoor' in result:
                data['building'] = result['indoor']['building']
            return data
        else:
            return
    except Exception as e:
        return

def wifidb_bssid(bssid_param):
    """Searches for a network with a specific BSSID in the wifidb database.

    Parameters:
        bssid_param (str): The BSSID of the network to search for.

    Returns:
        list: A list of dictionaries, each containing information about a network. If an error occurred, the list will contain a single dictionary with an error message.
    """
    # Set the endpoint for the request
    endpoint = 'https://wifidb.net/wifidb/api/geojson.php'
    # Set the parameters for the request
    params = {
        'func': 'exp_search',
        'ssid': '',
        'mac': bssid_param,
        'radio': '',
        'chan': '',
        'auth': '',
        'encry': '',
        'sectype': '',
        'json': '0',
        'labeled': '0'
    }
    try:
        # Send the GET request
        response = requests.get(
            endpoint,
            params=params,
            # Disable SSL verification if specified in the configuration data
            verify=False
        )
        # If the request is successful
        if response.status_code == 200:
            # Get the results from the response
            results = response.json()['features']
            # Create a list of dictionaries containing the data
            data = [{
                'module': 'wifidb',
                'bssid': result['properties']['mac'],
                'ssid': result['properties']['ssid'],
                'latitude': result['properties']['lat'],
                'longitude': result['properties']['lon']
            } for result in results]
            return data
    except Exception as e:
        print(e)

def search_networks(bssid=None, ssid=None):
    """Searches for networks using the specified search criteria.

    Parameters:
        bssid (str, optional): The BSSID of the network to search for.
        ssid (str, optional): The SSID of the network to search for.

    Returns:
        list: A list of dictionaries, each containing information about a network.
    """

    # Initialize an empty list to store the results
    results = []

    # Create a list of functions to be called concurrently
    functions = []
    if bssid:
        functions.extend(
            [wigle_bssid, apple_bssid, mylnikov_bssid, google_bssid, combain_bssid, wifidb_bssid])
    if ssid:
        functions.extend([wigle_ssid, openwifimap_ssid, wifidb_ssid, freifunk_karte_ssid])

    # Use a ThreadPoolExecutor to call the functions concurrently
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Create a list of futures for each function
        futures = [executor.submit(f, bssid or ssid) for f in functions]

        # Iterate over the completed futures
        for future in concurrent.futures.as_completed(futures):
            try:
                # Get the result from the future
                result = future.result()

                # Check if the result is valid
                if result:
                    # Add the result to the list of results
                    if bssid:
                        if isinstance(result, list):
                            for res in result:
                                if str(res['bssid']).lower() == str(bssid).lower():
                                    if res['latitude'] != 0.0:
                                        results.append(res)
                        else:
                            results.append(result)
                    if ssid:
                        if isinstance(result, list):
                            for res in result:
                                if str(res['ssid']).lower() == str(ssid).lower():
                                    if res['latitude'] != 0.0:
                                        results.append(res)
                        else:
                            results.append(result)
            except Exception as e:
                print(f"Error processing result: {e}")

    # Format the json data
    for locations in results:
        if 'latitude' in locations:
            locations['latitude'] = float(locations['latitude'])
        if 'longitude' in locations:
            locations['longitude'] = float(locations['longitude'])

    return results

@app.route('/geowifi', methods=['POST'])
def search_geowifi():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing data'}), 400

    # Extract search parameters from JSON
    ssid = data.get('ssid', None)
    bssid = data.get('bssid', None)

    # Perform search using geowifi library
    results = search_networks(ssid=ssid, bssid=bssid)

    # Return search results as JSON
    return jsonify(results)

if __name__ == '__main__':
    app.run(host="0.0.0.0")