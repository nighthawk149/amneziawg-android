/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.viewmodel

import android.os.Parcel
import android.os.Parcelable
import androidx.databinding.BaseObservable
import androidx.databinding.Bindable
import androidx.databinding.ObservableArrayList
import androidx.databinding.ObservableList
import com.wireguard.android.BR
import com.wireguard.config.Attribute
import com.wireguard.config.BadConfigException
import com.wireguard.config.Interface
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyFormatException
import com.wireguard.crypto.KeyPair

class InterfaceProxy : BaseObservable, Parcelable {
    @get:Bindable
    val excludedApplications: ObservableList<String> = ObservableArrayList()

    @get:Bindable
    val includedApplications: ObservableList<String> = ObservableArrayList()

    @get:Bindable
    var addresses: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.addresses)
        }

    @get:Bindable
    var dnsServers: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.dnsServers)
        }

    @get:Bindable
    var listenPort: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.listenPort)
        }

    @get:Bindable
    var mtu: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.mtu)
        }

    @get:Bindable
    var jc: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.jc)
        }

    @get:Bindable
    var jmin: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.jmin)
        }

    @get:Bindable
    var jmax: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.jmax)
        }

    @get:Bindable
    var s1: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.s1)
        }

    @get:Bindable
    var s2: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.s2)
        }

    @get:Bindable
    var h1: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.h1)
        }

    @get:Bindable
    var h2: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.h2)
        }

    @get:Bindable
    var h3: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.h3)
        }

    @get:Bindable
    var h4: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.h4)
        }

    @get:Bindable
    var privateKey: String = ""
        set(value) {
            field = value
            notifyPropertyChanged(BR.privateKey)
            notifyPropertyChanged(BR.publicKey)
        }

    @get:Bindable
    val publicKey: String
        get() = try {
            KeyPair(Key.fromBase64(privateKey)).publicKey.toBase64()
        } catch (ignored: KeyFormatException) {
            ""
        }

    private constructor(parcel: Parcel) {
        addresses = parcel.readString() ?: ""
        dnsServers = parcel.readString() ?: ""
        parcel.readStringList(excludedApplications)
        parcel.readStringList(includedApplications)
        listenPort = parcel.readString() ?: ""
        mtu = parcel.readString() ?: ""
        jc = parcel.readString() ?: ""
        jmin = parcel.readString() ?: ""
        jmax = parcel.readString() ?: ""
        privateKey = parcel.readString() ?: ""
    }

    constructor(other: Interface) {
        addresses = Attribute.join(other.addresses)
        val dnsServerStrings = other.dnsServers.map { it.hostAddress }.plus(other.dnsSearchDomains)
        dnsServers = Attribute.join(dnsServerStrings)
        excludedApplications.addAll(other.excludedApplications)
        includedApplications.addAll(other.includedApplications)
        listenPort = other.listenPort.map { it.toString() }.orElse("")
        mtu = other.mtu.map { it.toString() }.orElse("")
        val keyPair = other.keyPair
        privateKey = keyPair.privateKey.toBase64()
        jc = other.jc.map { it.toString() }.orElse("")
        jmin = other.jmin.map { it.toString() }.orElse("")
        jmax = other.jmax.map { it.toString() }.orElse("")
        s1 = other.s1.map { it.toString() }.orElse("")
        s2 = other.s2.map { it.toString() }.orElse("")
        h1 = other.h1.map { it.toString() }.orElse("")
        h2 = other.h2.map { it.toString() }.orElse("")
        h3 = other.h3.map { it.toString() }.orElse("")
        h4 = other.h4.map { it.toString() }.orElse("")
    }

    constructor()

    override fun describeContents() = 0

    fun generateKeyPair() {
        val keyPair = KeyPair()
        privateKey = keyPair.privateKey.toBase64()
        notifyPropertyChanged(BR.privateKey)
        notifyPropertyChanged(BR.publicKey)
    }

    @Throws(BadConfigException::class)
    fun resolve(): Interface {
        val builder = Interface.Builder()
        if (addresses.isNotEmpty()) builder.parseAddresses(addresses)
        if (dnsServers.isNotEmpty()) builder.parseDnsServers(dnsServers)
        if (excludedApplications.isNotEmpty()) builder.excludeApplications(excludedApplications)
        if (includedApplications.isNotEmpty()) builder.includeApplications(includedApplications)
        if (listenPort.isNotEmpty()) builder.parseListenPort(listenPort)
        if (mtu.isNotEmpty()) builder.parseMtu(mtu)
        if (privateKey.isNotEmpty()) builder.parsePrivateKey(privateKey)
        if (jc.isNotEmpty()) builder.parseJc(jc)
        if (jmin.isNotEmpty()) builder.parseJmin(jmin)
        if (jmax.isNotEmpty()) builder.parseJmax(jmax)
        if (s1.isNotEmpty()) builder.parseS1(s1)
        if (s2.isNotEmpty()) builder.parseS2(s2)
        if (h1.isNotEmpty()) builder.parseH1(h1)
        if (h2.isNotEmpty()) builder.parseH2(h2)
        if (h3.isNotEmpty()) builder.parseH3(h3)
        if (h4.isNotEmpty()) builder.parseH4(h4)
        return builder.build()
    }

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeString(addresses)
        dest.writeString(dnsServers)
        dest.writeStringList(excludedApplications)
        dest.writeStringList(includedApplications)
        dest.writeString(listenPort)
        dest.writeString(mtu)
        dest.writeString(privateKey)
        dest.writeString(jc)
        dest.writeString(jmin)
        dest.writeString(jmax)
        dest.writeString(s1)
        dest.writeString(s2)
        dest.writeString(h1)
        dest.writeString(h2)
        dest.writeString(h3)
        dest.writeString(h4)
    }

    private class InterfaceProxyCreator : Parcelable.Creator<InterfaceProxy> {
        override fun createFromParcel(parcel: Parcel): InterfaceProxy {
            return InterfaceProxy(parcel)
        }

        override fun newArray(size: Int): Array<InterfaceProxy?> {
            return arrayOfNulls(size)
        }
    }

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<InterfaceProxy> = InterfaceProxyCreator()
    }
}
