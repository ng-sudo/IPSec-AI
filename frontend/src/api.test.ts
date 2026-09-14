import { afterEach, describe, expect, it, vi } from 'vitest'
import { analyzeCapture, listCaptures } from './api'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('dashboard API client', () => {
  it('loads captures and posts analysis configuration', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify([{ capture_id: 'cap-1', filename: 'sample.pcap', size_bytes: 20 }]), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ capture_id: 'cap-1' }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(listCaptures()).resolves.toEqual([{ capture_id: 'cap-1', filename: 'sample.pcap', size_bytes: 20 }])
    await analyzeCapture('cap-1', { ipsec_mode: 'tunnel' })

    expect(fetchMock).toHaveBeenLastCalledWith(
      'http://127.0.0.1:8000/api/v1/captures/cap-1/analyze',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ vpn_configuration: { ipsec_mode: 'tunnel' } }),
      }),
    )
  })

  it('surfaces backend errors to the dashboard', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: 'capture not found' }), { status: 404 })))

    await expect(listCaptures()).rejects.toThrow('capture not found')
  })
})
