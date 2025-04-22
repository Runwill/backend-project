import axios from 'axios';

class ApiService {
    constructor(baseURL) {
        this.client = axios.create({
            baseURL: baseURL,
            timeout: 1000,
        });
    }

    async get(endpoint) {
        try {
            const response = await this.client.get(endpoint);
            return response.data;
        } catch (error) {
            throw new Error(`Error fetching data from ${endpoint}: ${error.message}`);
        }
    }

    async post(endpoint, data) {
        try {
            const response = await this.client.post(endpoint, data);
            return response.data;
        } catch (error) {
            throw new Error(`Error posting data to ${endpoint}: ${error.message}`);
        }
    }

    async put(endpoint, data) {
        try {
            const response = await this.client.put(endpoint, data);
            return response.data;
        } catch (error) {
            throw new Error(`Error updating data at ${endpoint}: ${error.message}`);
        }
    }

    async delete(endpoint) {
        try {
            const response = await this.client.delete(endpoint);
            return response.data;
        } catch (error) {
            throw new Error(`Error deleting data at ${endpoint}: ${error.message}`);
        }
    }
}

export default new ApiService(process.env.API_BASE_URL);